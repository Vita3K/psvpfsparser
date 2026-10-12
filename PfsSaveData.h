#pragma once

#include <cstdint>
#include <iostream>
#include <map>
#include <string>

#include "LocalFilesystem.h"
#include "PfsProgress.h"

//decrypts a savedata folder copied from a PS Vita, its keys come from sce_sys/sealedkey
int decrypt_savedata(const psvpfs::path& src, const psvpfs::path& dst, PfsProgressCallback progress = nullptr, std::ostream& output = std::cout);

//builds the encrypted PFS image of a decrypted savedata folder, which must contain sce_sys/sealedkey
//fixed_ids maps upper case relative paths (like SCE_SYS/SDSLOT.DAT) to file ids, other ids are random
int encrypt_savedata(const psvpfs::path& src, const psvpfs::path& dst, PfsProgressCallback progress = nullptr, std::ostream& output = std::cout, const std::map<std::string, std::uint32_t>* fixed_ids = nullptr);
