#include "PfsSaveData.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <set>
#include <vector>

#include "CryptoOperationsFactory.h"
#include "F00DKeyEncryptorFactory.h"
#include "FilesDbParser.h"
#include "FlagOperations.h"
#include "LocalKeyGenerator.h"
#include "MerkleTree.hpp"
#include "PfsCryptEngine.h"
#include "PfsCryptEngineSelectors.h"
#include "PfsFilesystem.h"
#include "PfsKeyGenerator.h"
#include "SecretGenerator.h"
#include "UnicvDbTypes.h"
#include "UnicvDbUtils.h"

namespace {

constexpr std::uint32_t PAGE_SIZE = 0x400;
constexpr std::uint32_t SECTOR_SIZE = 0x8000;
constexpr std::uint16_t SAVEDATA_IMAGE_SPEC = 2;
constexpr std::uint32_t NAME_SIZE = 68;
constexpr std::uint32_t MAX_KEYS_IN_NODE = 9;
constexpr std::uint32_t MAX_CHILDREN_IN_NODE = 10;
constexpr std::uint32_t NO_INDEX = 0xFFFFFFFF;
constexpr std::uint32_t DIRECTORY_SIZE = 0x10000;

struct Entry
{
   std::string key; //upper case relative path
   std::string name; //upper case file name
   psvpfs::path real;
   std::uint32_t parent = 0;
   std::uint32_t idx = 0;
   std::uint16_t type = 0;
   std::uint32_t size = 0;
   unsigned char hash[0x14] = {};
};

struct Context
{
   std::shared_ptr<ICryptoOperations> cryptops;
   std::shared_ptr<IF00DKeyEncryptor> iF00D;
   unsigned char klicensee[0x10];
   std::uint16_t crypto_flag;
};

std::string to_upper(std::string s)
{
   std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
   return s;
}

void put32(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint32_t value)
{
   memcpy(buf.data() + offset, &value, sizeof(value));
}

void put64(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value)
{
   memcpy(buf.data() + offset, &value, sizeof(value));
}

void get_secret(const Context& ctx, std::uint32_t icv_salt, unsigned char* secret)
{
   scePfsUtilGetSecret(ctx.cryptops, ctx.iF00D, secret, ctx.klicensee, 0, ctx.crypto_flag, icv_salt, 0);
}

std::uint16_t file_type(bool is_dir, bool at_root, bool in_sce_sys, const std::string& name)
{
   if(is_dir)
      return at_root && name == "SCE_SYS" ? static_cast<std::uint16_t>(sce_ng_pfs_file_types::sys_directory) : ATTR_DIR;
   if(!in_sce_sys)
      return 0;
   if(name == "KEYSTONE")
      return static_cast<std::uint16_t>(sce_ng_pfs_file_types::encrypted_system_file_ro);
   if(name == "SEALEDKEY")
      return static_cast<std::uint16_t>(sce_ng_pfs_file_types::unencrypted_system_file_ro);
   if(name == "PARAM.SFO")
      return static_cast<std::uint16_t>(sce_ng_pfs_file_types::unencrypted_system_file_rw);
   if(name == "SAFEMEM.DAT" || name == "_SAFEMEM.DAT")
      return static_cast<std::uint16_t>(sce_ng_pfs_file_types::encrypted_system_file_rw);
   return 0;
}

//merkle tree helpers, the same shapes as the ones verified by PfsPageMapper

int assign_leaf(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   if(node->isLeaf())
      node->m_context = (*static_cast<std::vector<icv>*>(ctx))[node->m_index];
   return 0;
}

int combine_nodes(std::shared_ptr<merkle_tree_node<icv> > result, std::shared_ptr<merkle_tree_node<icv> > left, std::shared_ptr<merkle_tree_node<icv> > right, void* ctx)
{
   auto* c = static_cast<std::pair<const Context*, const unsigned char*>*>(ctx);
   unsigned char both[0x28];
   memcpy(both, left->m_context.m_data.data(), 0x14);
   memcpy(both + 0x14, right->m_context.m_data.data(), 0x14);
   result->m_context.m_data.resize(0x14);
   c->first->cryptops->hmac_sha1(both, result->m_context.m_data.data(), 0x28, c->second, 0x14);
   return 0;
}

int collect_node(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   static_cast<std::vector<icv>*>(ctx)->push_back(node->m_context);
   return 0;
}

std::vector<icv> build_merkle_page(const Context& ctx, const unsigned char* secret, std::vector<icv> leaves)
{
   std::shared_ptr<merkle_tree<icv> > mkt = generate_merkle_tree<icv>(static_cast<std::uint32_t>(leaves.size()));
   index_merkle_tree(mkt);
   walk_tree(mkt, assign_leaf, &leaves);
   auto combine_ctx = std::make_pair(&ctx, secret);
   bottom_top_walk_combine(mkt, combine_nodes, &combine_ctx);
   std::vector<icv> hashes;
   walk_tree(mkt, collect_node, &hashes);
   return hashes;
}

std::vector<std::uint8_t> make_signature_page(std::uint32_t level, const std::vector<icv>& hashes, const std::vector<std::uint32_t>& tail)
{
   std::vector<std::uint8_t> page(PAGE_SIZE);
   put32(page, 0x00, level);
   put32(page, 0x10, binTreeSize(0x14, ICV_NUM_ENTRIES));
   put32(page, 0x14, 0x14);
   put32(page, 0x18, static_cast<std::uint32_t>(hashes.size()));
   for(std::size_t i = 0; i < hashes.size(); i++)
      memcpy(page.data() + 0x20 + i * 0x14, hashes[i].m_data.data(), 0x14);
   for(std::size_t i = 0; i < tail.size(); i++)
      put32(page, PAGE_SIZE - 0x5C + i * 4, tail[i]);
   return page;
}

//sector hashes are grouped by ICV_SECTORS_PER_PAGE into pages that hold their merkle tree
//with more than one such page a level 1 page holds the merkle tree of their roots
//the level 1 page is stored right after the first two level 0 pages, like the PS Vita does
bool build_icv_file(const Context& ctx, const unsigned char* secret, const std::vector<icv>& sector_hashes, std::vector<std::uint8_t>& out, std::ostream& output)
{
   const std::uint32_t nSectors = static_cast<std::uint32_t>(sector_hashes.size());
   const std::uint32_t nLeafPages = (nSectors + ICV_SECTORS_PER_PAGE - 1) / ICV_SECTORS_PER_PAGE;
   if(nLeafPages > ICV_SECTORS_PER_PAGE)
   {
      output << "File is too large for a two level icv table" << std::endl;
      return false;
   }

   std::vector<std::vector<icv> > leaf_pages;
   std::vector<icv> roots;
   for(std::uint32_t first = 0; first < nSectors; first += ICV_SECTORS_PER_PAGE)
   {
      std::uint32_t n = std::min<std::uint32_t>(ICV_SECTORS_PER_PAGE, nSectors - first);
      leaf_pages.push_back(build_merkle_page(ctx, secret, std::vector<icv>(sector_hashes.begin() + first, sector_hashes.begin() + first + n)));
      roots.push_back(leaf_pages.back().front());
   }

   std::vector<std::vector<std::uint8_t> > pages;
   std::uint32_t rootPageIndex = 0;
   icv rootHash = roots.front();
   if(nLeafPages == 1)
   {
      pages.push_back(make_signature_page(0, leaf_pages[0], std::vector<std::uint32_t>(nSectors, NO_INDEX)));
   }
   else
   {
      rootPageIndex = 2;
      std::vector<std::uint32_t> leafPageIndices;
      for(std::uint32_t i = 0; i < nLeafPages; i++)
         leafPageIndices.push_back(i < 2 ? i : i + 1);

      std::vector<icv> top = build_merkle_page(ctx, secret, roots);
      rootHash = top.front();

      pages.resize(nLeafPages + 1);
      pages[rootPageIndex] = make_signature_page(1, top, leafPageIndices);
      for(std::uint32_t i = 0; i < nLeafPages; i++)
      {
         std::uint32_t n = std::min<std::uint32_t>(ICV_SECTORS_PER_PAGE, nSectors - i * ICV_SECTORS_PER_PAGE);
         pages[leafPageIndices[i]] = make_signature_page(0, leaf_pages[i], std::vector<std::uint32_t>(n, NO_INDEX));
      }
   }

   out.assign(PAGE_SIZE, 0);
   memcpy(out.data(), CV_DB_MAGIC_WORD, 8);
   put32(out, 0x08, ICV_EXPECTED_VERSION_2);
   put32(out, 0x0C, SECTOR_SIZE);
   put32(out, 0x10, PAGE_SIZE);
   put32(out, 0x14, rootPageIndex);
   put32(out, 0x18, NO_INDEX);
   put32(out, 0x1C, NO_INDEX);
   put64(out, 0x20, static_cast<std::uint64_t>(pages.size()) * PAGE_SIZE);
   put32(out, 0x28, nSectors);
   memcpy(out.data() + 0x2C, rootHash.m_data.data(), 0x14);
   for(auto& p : pages)
      out.insert(out.end(), p.begin(), p.end());
   return true;
}

std::vector<std::uint8_t> make_inull_file()
{
   std::vector<std::uint8_t> out(sizeof(sce_inull_header_t));
   memcpy(out.data(), NULL_MAGIC_WORD, 8);
   put32(out, 0x08, NULL_EXPECTED_VERSION);
   return out;
}

bool write_file(const psvpfs::path& path, const std::vector<std::uint8_t>& data)
{
   std::ofstream os(path, std::ios::binary | std::ios::trunc);
   os.write(reinterpret_cast<const char*>(data.data()), data.size());
   return static_cast<bool>(os);
}

bool encrypt_file(const Context& ctx, Entry& e, const psvpfs::path& dst, const psvpfs::path& icv_dir, std::ostream& output)
{
   unsigned char secret[0x14];
   get_secret(ctx, e.idx, secret);

   std::vector<std::uint8_t> icv_file;
   std::vector<std::uint8_t> data;
   if(e.type & ATTR_DIR)
   {
      psvpfs::create_directories(dst);
      icv_file = make_inull_file();
   }
   else
   {
      std::ifstream is(e.real, std::ios::binary | std::ios::ate);
      const std::streamoff size = is.tellg();
      if(!is || size < 0)
      {
         output << "Failed to open " << e.real << std::endl;
         return false;
      }
      data.resize(static_cast<std::size_t>(size));
      if(!is.seekg(0) || !is.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size())))
      {
         output << "Failed to read " << e.real << std::endl;
         return false;
      }
      e.size = static_cast<std::uint32_t>(data.size());
      if(data.empty())
      {
         icv_file = make_inull_file();
      }
      else
      {
         data.resize((data.size() + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE);

         if(!(e.type & ATTR_NENC))
         {
            CryptEngineData cd;
            memset(&cd, 0, sizeof(cd));
            cd.klicensee = ctx.klicensee;
            cd.icv_salt = e.idx;
            cd.mode_index = img_spec_to_mode_index(SAVEDATA_IMAGE_SPEC);
            cd.crypto_engine_flag = ctx.crypto_flag | CRYPTO_ENGINE_THROW_ERROR;
            cd.fs_attr = e.type;
            cd.block_size = SECTOR_SIZE;

            derive_keys_ctx drv;
            memset(&drv, 0, sizeof(drv));
            drv.db_type = settings_to_db_type(cd.mode_index, cd.fs_attr);
            drv.icv_version = ICV_EXPECTED_VERSION_2;
            setup_crypt_packet_keys(ctx.cryptops, ctx.iF00D, &cd, &drv);

            for(std::size_t offset = 0; offset < data.size(); offset += SECTOR_SIZE)
            {
               if(pfs_encrypt_icv(ctx.cryptops, cd.dec_key, cd.tweak_enc_key, 0x80, offset, SECTOR_SIZE, SECTOR_SIZE, data.data() + offset, data.data() + offset, cd.crypto_engine_flag) != 0)
               {
                  output << "Failed to encrypt " << e.key << std::endl;
                  return false;
               }
            }
         }

         std::vector<icv> sector_hashes(data.size() / SECTOR_SIZE);
         for(std::size_t s = 0; s < sector_hashes.size(); s++)
         {
            sector_hashes[s].m_data.resize(0x14);
            ctx.cryptops->hmac_sha1(data.data() + s * SECTOR_SIZE, sector_hashes[s].m_data.data(), SECTOR_SIZE, secret, 0x14);
         }

         if(!build_icv_file(ctx, secret, sector_hashes, icv_file, output))
            return false;
      }

      if(!write_file(dst, data))
      {
         output << "Failed to write " << dst << std::endl;
         return false;
      }
   }

   //files.db keeps the hmac of the icv table header for each entry
   const std::size_t hashed = std::min<std::size_t>(icv_file.size(), 0x40);
   ctx.cryptops->hmac_sha1(icv_file.data(), e.hash, static_cast<int>(hashed), secret, 0x14);

   char icv_name[16];
   snprintf(icv_name, sizeof(icv_name), "%08x.icv", e.idx);
   if(!write_file(icv_dir / icv_name, icv_file))
   {
      output << "Failed to write icv for " << e.key << std::endl;
      return false;
   }
   return true;
}

struct Node
{
   std::uint32_t page = 0;
   bool leaf = true;
   std::vector<const Entry*> keys; //entries for leaves, separators for internal nodes
   std::vector<Node*> children;
   const Entry* first = nullptr;
   unsigned char icv[0x14] = {};
};

//splits n items into the fewest groups of at most max_size items with balanced sizes
std::vector<std::size_t> balanced_groups(std::size_t n, std::size_t max_size)
{
   std::size_t groups = (n + max_size - 1) / max_size;
   std::vector<std::size_t> sizes(groups, n / groups);
   for(std::size_t i = 0; i < n % groups; i++)
      sizes[i]++;
   return sizes;
}

std::vector<std::uint8_t> build_files_db(const Context& ctx, const std::vector<Entry>& entries)
{
   std::vector<std::unique_ptr<Node> > nodes;
   std::vector<Node*> level;

   std::size_t pos = 0;
   for(std::size_t n : balanced_groups(entries.size(), MAX_KEYS_IN_NODE))
   {
      nodes.push_back(std::make_unique<Node>());
      Node* node = nodes.back().get();
      for(std::size_t i = 0; i < n; i++)
         node->keys.push_back(&entries[pos++]);
      node->first = node->keys.front();
      level.push_back(node);
   }
   const std::vector<Node*> leaves = level;

   while(level.size() > 1)
   {
      std::vector<Node*> upper;
      std::size_t c = 0;
      for(std::size_t n : balanced_groups(level.size(), MAX_CHILDREN_IN_NODE))
      {
         nodes.push_back(std::make_unique<Node>());
         Node* node = nodes.back().get();
         node->leaf = false;
         for(std::size_t i = 0; i < n; i++, c++)
         {
            if(i > 0)
               node->keys.push_back(level[c]->first);
            node->children.push_back(level[c]);
         }
         node->first = level[c - n]->first;
         upper.push_back(node);
      }
      level = upper;
   }
   Node* root = level.front();

   for(std::size_t i = 0; i < nodes.size(); i++)
      nodes[i]->page = static_cast<std::uint32_t>(i);

   unsigned char secret[0x14];
   get_secret(ctx, 0, secret);

   std::vector<std::uint8_t> db(PAGE_SIZE + nodes.size() * PAGE_SIZE, 0);
   std::map<const Node*, std::uint32_t> parents;
   for(auto& n : nodes)
      for(Node* child : n->children)
         parents[child] = n->page;

   //children always come before their parents in nodes, so their icvs are ready
   for(std::size_t i = 0; i < nodes.size(); i++)
   {
      Node* node = nodes[i].get();
      std::vector<std::uint8_t> page(PAGE_SIZE, 0);
      put32(page, 0x00, node == root ? NO_INDEX : parents[node]);
      put32(page, 0x04, node->leaf ? sce_ng_pfs_block_types::child : sce_ng_pfs_block_types::root);
      put32(page, 0x08, static_cast<std::uint32_t>(node->keys.size()));

      for(std::size_t k = 0; k < node->keys.size(); k++)
      {
         put32(page, 0x10 + k * 0x48, node->keys[k]->parent);
         memcpy(page.data() + 0x14 + k * 0x48, node->keys[k]->name.data(), node->keys[k]->name.size());
      }

      const std::size_t infos = 0x10 + MAX_KEYS_IN_NODE * 0x48;
      const std::size_t hashes = infos + MAX_CHILDREN_IN_NODE * 0x10;
      for(std::size_t k = 0; k < MAX_CHILDREN_IN_NODE; k++)
         put32(page, infos + k * 0x10, NO_INDEX);

      std::vector<const unsigned char*> chain;
      if(node->leaf)
      {
         for(std::size_t k = 0; k < node->keys.size(); k++)
         {
            const Entry* e = node->keys[k];
            put32(page, infos + k * 0x10, e->idx);
            memcpy(page.data() + infos + k * 0x10 + 4, &e->type, 2);
            put32(page, infos + k * 0x10 + 8, e->size);
            memcpy(page.data() + hashes + k * 0x14, e->hash, 0x14);
            chain.push_back(e->hash);
         }
         auto next = std::find(leaves.begin(), leaves.end(), node) + 1;
         if(next != leaves.end())
            put32(page, infos + (MAX_CHILDREN_IN_NODE - 1) * 0x10, (*next)->page);
      }
      else
      {
         for(std::size_t k = 0; k < node->children.size(); k++)
         {
            put32(page, infos + k * 0x10, node->children[k]->page);
            put32(page, infos + k * 0x10 + 4, 0);
            memcpy(page.data() + hashes + k * 0x14, node->children[k]->icv, 0x14);
            chain.push_back(node->children[k]->icv);
         }
      }

      for(const unsigned char* h : chain)
      {
         unsigned char both[0x28];
         memcpy(both, node->icv, 0x14);
         memcpy(both + 0x14, h, 0x14);
         ctx.cryptops->hmac_sha1(both, node->icv, 0x28, secret, 0x14);
      }

      memcpy(db.data() + PAGE_SIZE + node->page * PAGE_SIZE, page.data(), PAGE_SIZE);
   }

   std::uint64_t total = 0;
   for(auto& e : entries)
      total += (e.type & ATTR_DIR) ? e.size : (static_cast<std::uint64_t>(e.size) + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE + SECTOR_SIZE;

   memcpy(db.data(), "SCENGPFS", 8);
   put32(db, 0x08, 3);
   std::uint16_t spec = SAVEDATA_IMAGE_SPEC;
   memcpy(db.data() + 0x0C, &spec, 2);
   put32(db, 0x10, PAGE_SIZE);
   put32(db, 0x14, MAX_CHILDREN_IN_NODE);
   put32(db, 0x18, root->page);
   put32(db, 0x1C, 0);
   put64(db, 0x20, 0xFFFFFFFFFFFFFFFFull);
   put64(db, 0x28, static_cast<std::uint64_t>(nodes.size()) * PAGE_SIZE);
   put64(db, 0x30, total);
   memcpy(db.data() + 0x38, root->icv, 0x14);
   ctx.cryptops->hmac_sha1(db.data(), db.data() + 0x4C, 0x160, secret, 0x14);
   return db;
}

} // namespace

int decrypt_savedata(const psvpfs::path& src, const psvpfs::path& dst, PfsProgressCallback progress, std::ostream& output)
{
   auto cryptops = CryptoOperationsFactory::create(CryptoOperationsTypes::openssl);
   auto iF00D = F00DKeyEncryptorFactory::create(F00DEncryptorTypes::native, cryptops);
   unsigned char klicensee[0x10];
   if(get_sealedkey(cryptops, src, klicensee) < 0)
   {
      output << "sce_sys/sealedkey is missing or invalid" << std::endl;
      return -1;
   }

   PfsFilesystem pfs(cryptops, iF00D, output, klicensee, src);
   if(pfs.mount() < 0)
      return -1;
   return pfs.decrypt_files(dst, progress);
}

int encrypt_savedata(const psvpfs::path& src, const psvpfs::path& dst, PfsProgressCallback progress, std::ostream& output, const std::map<std::string, std::uint32_t>* fixed_ids)
{
   Context ctx;
   ctx.cryptops = CryptoOperationsFactory::create(CryptoOperationsTypes::openssl);
   ctx.iF00D = F00DKeyEncryptorFactory::create(F00DEncryptorTypes::native, ctx.cryptops);
   ctx.crypto_flag = img_spec_to_crypto_engine_flag(SAVEDATA_IMAGE_SPEC);
   if(get_sealedkey(ctx.cryptops, src, ctx.klicensee) < 0)
   {
      output << "sce_sys/sealedkey is missing or invalid" << std::endl;
      return -1;
   }

   std::random_device rd;
   std::mt19937 rng(rd());
   std::set<std::uint32_t> used_ids;
   if(fixed_ids)
      for(auto& it : *fixed_ids)
         used_ids.insert(it.second);

   std::vector<Entry> entries;
   std::map<psvpfs::path, std::uint32_t> dir_ids;
   std::uint64_t total_bytes = 0;
   for(auto it = psvpfs::recursive_directory_iterator(src); it != psvpfs::recursive_directory_iterator(); ++it)
   {
      const psvpfs::path rel = psvpfs::relative(it->path(), src);
      if(it.depth() == 0 && to_upper(rel.generic_string()) == "SCE_PFS")
      {
         it.disable_recursion_pending();
         continue;
      }

      Entry e;
      e.real = it->path();
      e.key = to_upper(rel.generic_string());
      e.name = to_upper(rel.filename().generic_string());
      if(e.name.size() >= NAME_SIZE)
      {
         output << "File name is too long: " << rel.generic_string() << std::endl;
         return -1;
      }
      e.parent = rel.has_parent_path() ? dir_ids.at(rel.parent_path()) : 0;
      const bool in_sce_sys = to_upper(rel.parent_path().generic_string()) == "SCE_SYS";
      e.type = file_type(it->is_directory(), !rel.has_parent_path(), in_sce_sys, e.name);
      e.size = it->is_directory() ? DIRECTORY_SIZE : static_cast<std::uint32_t>(it->file_size());

      if(fixed_ids && fixed_ids->count(e.key))
      {
         e.idx = fixed_ids->at(e.key);
      }
      else
      {
         do
            e.idx = static_cast<std::uint32_t>(rng());
         while(e.idx == 0 || e.idx == NO_INDEX || used_ids.count(e.idx));
         used_ids.insert(e.idx);
      }

      if(it->is_directory())
         dir_ids[rel] = e.idx;
      else
         total_bytes += e.size;
      entries.push_back(e);
   }

   const psvpfs::path icv_dir = dst / "sce_pfs" / "icv.db";
   psvpfs::create_directories(icv_dir);

   std::uint64_t done = 0;
   for(auto& e : entries)
   {
      if(!encrypt_file(ctx, e, dst / psvpfs::relative(e.real, src), icv_dir, output))
         return -1;
      if(!(e.type & ATTR_DIR))
      {
         done += e.size;
         if(progress)
            progress(done, total_bytes, e.key);
      }
   }

   std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
      return a.parent != b.parent ? a.parent < b.parent : a.name < b.name;
   });

   if(!write_file(dst / "sce_pfs" / "files.db", build_files_db(ctx, entries)))
   {
      output << "Failed to write files.db" << std::endl;
      return -1;
   }
   return 0;
}
