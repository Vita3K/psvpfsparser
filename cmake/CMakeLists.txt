set (PROJECT psvpfsparser)
project (${PROJECT})

message(${PROJECT})

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
                        "../psvpfsparser.cpp"
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
                        )
source_group ("Source Files" FILES ${SOURCE_FILES})

add_library(${PROJECT} ${HEADER_FILES} ${SOURCE_FILES} ${F00D_FILES} ${CRYPTO_FILES})

target_link_libraries(${PROJECT} host ${Boost_LIBRARIES} libzRIF libb64 zlib libtomcrypt)
target_include_directories(${PROJECT} PUBLIC .. ${Boost_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIR} ${LIBTOMCRYPT_INCLUDE_DIR} ${LIBB64_INCLUDE_DIR} ${LIBZRIF_INCLUDE_DIR})

