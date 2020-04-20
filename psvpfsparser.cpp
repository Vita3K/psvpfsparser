#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <zRIF/rif.h>
#include <zRIF/licdec.h>

#include "PfsFilesystem.h"

#include "F00DKeyEncryptorFactory.h"
#include "CryptoOperationsFactory.h"
#include "PsvPfsParserConfig.h"
#include "LocalKeyGenerator.h"

int execute(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, const unsigned char* klicensee, boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath)
{
   PfsFilesystem pfs(cryptops, iF00D, std::cout, klicensee, titleIdPath);

   if(pfs.mount() < 0)
      return -1;
   
   if(pfs.decrypt_files(destTitleIdPath) < 0)
      return -1;

   std::cout << "keystone sanity check..." << std::endl;

   if(get_keystone(cryptops, destTitleIdPath) < 0)
      return -1;

   std::cout << "F00D cache:" << std::endl;
   iF00D->print_cache(std::cout);

   return 0;
}

int extract_klicensee(const HostState &host, std::shared_ptr<ICryptoOperations> cryptops, unsigned char* klicensee)
{
   if(host.klicensee.length() > 0)
   {
      if(string_to_byte_array(host.klicensee, 0x10, klicensee) < 0)
      {
         std::cout << "Failed to parse klicensee" << std::endl;
         return -1;
      }
   }
   else if(host.zRIF.length() > 0)
   {
      std::shared_ptr<SceNpDrmLicense> lic = decode_license_np(host.zRIF);
      if(!lic)
      {
         std::cout << "Failed to decode zRIF string" << std::endl;
         return -1;
      }
      memcpy(klicensee, lic->key, 0x10);
   }
   else
   {
      std::cout << "using sealedkey..." << std::endl;
      
      if(get_sealedkey(cryptops, host.title_id_src, klicensee) < 0)
         return -1;
   }

   return 0;
}

std::shared_ptr<IF00DKeyEncryptor> create_F00D_encryptor(const HostState &host, std::shared_ptr<ICryptoOperations> cryptops)
{
   std::shared_ptr<IF00DKeyEncryptor> iF00D;

   switch(host.f00d_enc_type)
   {
      case F00DEncryptorTypes::file:
         iF00D = F00DKeyEncryptorFactory::create(host.f00d_enc_type, host.f00d_arg); 
         break;
      case F00DEncryptorTypes::native:
         iF00D = F00DKeyEncryptorFactory::create(host.f00d_enc_type, cryptops); 
         break;
      default:
         throw std::runtime_error("unexpected F00DEncryptorTypes value");
   }

   return iF00D;
}

int execute(const HostState &host)
{
   std::shared_ptr<ICryptoOperations> cryptops = CryptoOperationsFactory::create(CryptoOperationsTypes::libtomcrypt);
   std::shared_ptr<IF00DKeyEncryptor> iF00D = create_F00D_encryptor(host, cryptops);

   //trim slashes in source path
   
   boost::filesystem::path titleIdPath(host.title_id_src);
   std::string titleIdGen = titleIdPath.generic_string();
   boost::algorithm::trim_right_if(titleIdGen, [](char c){return c == '/';});
   titleIdPath = boost::filesystem::path(titleIdGen);

   //trim slashes in dest path
   boost::filesystem::path destTitleIdPath(host.title_id_dst);
   std::string destTitleIdPathGen = destTitleIdPath.generic_string();
   boost::algorithm::trim_right_if(destTitleIdPathGen, [](char c){return c == '/';});
   destTitleIdPath = boost::filesystem::path(destTitleIdPathGen);

   unsigned char klicensee[0x10] = {0};
   if(extract_klicensee(host, cryptops, klicensee) < 0)
      return -1;

   return execute(cryptops, iF00D, klicensee, titleIdPath, destTitleIdPath);
}

int pfsmain(int argc, char* argv[])
{
    HostState host;

   if(parse_options(argc, argv, host) < 0)
      return -1;

   try
   {
      execute(host);
   }
   catch(std::exception& e)
   {
      std::cout << "Error: " << e.what() << std::endl;
   }

   return 0;
}

