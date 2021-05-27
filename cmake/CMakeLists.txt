set (PROJECT psvpfsparser)
project (${PROJECT})

message(${PROJECT})

option(BUILD_EXAMPLES "Build Project Examples" ON)

FILE (GLOB F00D_FILES "../IF00DKeyEncryptor.h"
                      "../F00DFileKeyEncryptor.h"
                      "../F00DFileKeyEncryptor.cpp"
                      "../F00DKeyEncryptorFactory.h"
                      "../F00DKeyEncryptorFactory.cpp"
                      "../F00DNativeKeyEncryptor.h"
                      "../F00DNativeKeyEncryptor.cpp"
                      )
source_group ("F00D Files" FILES ${F00D_FILES})

FILE (GLOB CRYPTO_FILES "../ICryptoOperations.h"
                        "../LibTomCryptCryptoOperations.h"
                        "../LibTomCryptCryptoOperations.cpp"
                        "../CryptoOperationsFactory.h"
                        "../CryptoOperationsFactory.cpp"
                      )
source_group ("Crypto Files" FILES ${CRYPTO_FILES})

FILE (GLOB HEADER_FILES "../FilesDbParser.h"
                        "../HashTree.h"
                        "../NodeIcvCalculator.h"
                        "../PfsCryptEngine.h"
                        "../PfsCryptEngineBase.h"
                        "../PfsCryptEngineSelectors.h"
                        "../PfsKeyGenerator.h"
                        "../PfsKeys.h"
                        "../SceKernelUtilsForDriver.h"
                        "../SceSblSsMgrForDriver.h"
                        "../SecretGenerator.h"
                        "../UnicvDbParser.h"
                        "../UnicvDbTypes.h"
                        "../UnicvDbUtils.h"
                        "../Utils.h"
                        "../PsvPfsParserConfig.h"
                        "../LocalKeyGenerator.h"
                        "../LocalKeys.h"
                        "../MerkleTree.hpp"
                        "../IcvPrimitives.h"
                        "../FlagOperations.h"
                        "../PfsPageMapper.h"
                        "../PfsFilesystem.h"
                        "../PfsFile.h"
                        "../rif2zrif.h"
                        "../zrif2rif.h"
                        )
source_group ("Header Files" FILES ${HEADER_FILES})

FILE (GLOB SOURCE_FILES "../FilesDbParser.cpp"
                        "../HashTree.cpp"
                        "../NodeIcvCalculator.cpp"
                        "../PfsCryptEngine.cpp"
                        "../PfsCryptEngineBase.cpp"
                        "../PfsCryptEngineSelectors.cpp"
                        "../PfsKeyGenerator.cpp"
                        "../PfsKeys.cpp"
                        "../SceKernelUtilsForDriver.cpp"
                        "../SceSblSsMgrForDriver.cpp"
                        "../SecretGenerator.cpp"
                        "../UnicvDbParser.cpp"
                        "../UnicvDbTypes.cpp"
                        "../UnicvDbUtils.cpp"
                        "../Utils.cpp"
                        "../PsvPfsParserConfig.cpp"
                        "../LocalKeyGenerator.cpp"
                        "../LocalKeys.cpp"
                        "../IcvPrimitives.cpp"
                        "../FlagOperations.cpp"
                        "../PfsPageMapper.cpp"
                        "../PfsFilesystem.cpp"
                        "../PfsFile.cpp"
                        "../rif2zrif.cpp"
                        "../zrif2rif.cpp"
                        )
source_group ("Source Files" FILES ${SOURCE_FILES})

list(FIND CMAKE_CXX_KNOWN_FEATURES cxx_std_17 HAS_CXX17)

if(${HAS_CXX17})
    set(FILESYSTEM_NAMESPACE "std")
    set(FILESYSTEM_INCLUDE "filesystem")
else()
    set(FILESYSTEM_NAMESPACE "boost")
    set(FILESYSTEM_INCLUDE "boost/filesystem.hpp")

    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED ON)

    if(${BUILD_EXAMPLES})
        find_package(BOOST COMPONENTS filesystem system program_options REQUIRED)
    else()
        find_package(BOOST COMPONENTS filesystem system REQUIRED)
    endif()
endif()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/LocalFilesystem.h" "#pragma once

/*
    THIS IS AN AUTOMATICALLY GENERATED FILE. DO NOT EDIT!
*/

#include <${FILESYSTEM_INCLUDE}>

namespace psvpfs = ${FILESYSTEM_NAMESPACE}::filesystem;
")

add_library(${PROJECT} ${HEADER_FILES} ${SOURCE_FILES} ${F00D_FILES} ${CRYPTO_FILES})
target_link_libraries(${PROJECT} PUBLIC libzRIF libb64 zlib libtomcrypt)
target_include_directories(${PROJECT} PUBLIC .. ${CMAKE_CURRENT_BINARY_DIR} ${ZLIB_INCLUDE_DIR} ${LIBTOMCRYPT_INCLUDE_DIR} ${LIBB64_INCLUDE_DIR} ${LIBZRIF_INCLUDE_DIR})

if(NOT ${HAS_CXX17})
    target_link_libraries(${PROJECT} PRIVATE ${Boost_LIBRARIES})
    target_include_directories(${PROJECT} PRIVATE ${Boost_INCLUDE_DIRS})
    target_compile_options(${PROJECT} PRIVATE -DVPSVPFS_BOOST)

    if(${BUILD_EXAMPLES})
        add_executable(example_project MACOSX_BUNDLE "../example/psvpfsparserconfig.cpp")
        target_link_libraries(example_project PRIVATE ${PROJECT})
    endif()
else()
    target_compile_features(${PROJECT} PUBLIC cxx_std_17)
endif()
