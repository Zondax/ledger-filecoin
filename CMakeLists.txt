#*******************************************************************************
#*   (c) 2018 - 2024 Zondax AG
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
cmake_minimum_required(VERSION 3.28)
set(CMAKE_VERBOSE_MAKEFILE ON)
include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.26.1.tar.gz"
    SHA1 "e41ac7a18c49b35ebac99ff2b5244317b2638a65"
    LOCAL
)

if(CMAKE_GENERATOR MATCHES "Ninja")
    message(FATAL_ERROR "This project does not support the Ninja generator. "
                            "Please use Unix Makefiles or another supported generator. "
                            "This error is typical in CLion. In this case, switch to generator Unix Makefiles.")
endif()

########################################################
project(ledger-filecoin VERSION 0.0.0)

# Include common fuzzing configuration
include(deps/ledger-zxlib/fuzzing/FuzzingCommon.cmake)

set(CMAKE_CXX_STANDARD 20)
cmake_policy(SET CMP0025 NEW)
cmake_policy(SET CMP0144 NEW)

set(HUNTER_STATUS_DEBUG ON)
set(HUNTER_TLS_VERIFY OFF)

enable_testing()

string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_CXX_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -g")

hunter_add_package(fmt)
find_package(fmt CONFIG REQUIRED)

# Use FetchContent to get nlohmann_json 3.12.0 since Hunter doesn't support this version
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
)
FetchContent_MakeAvailable(nlohmann_json)

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

# Fuzzing configuration is now handled by FuzzingCommon.cmake
##############################################################
##############################################################
#  static libs
file(GLOB_RECURSE TINYCBOR_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src/cborparser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src/cborvalidation.c
        )

file(GLOB_RECURSE LIB_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/hexutils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/app_mode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/bignum.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/zxmacros.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/zxformat.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/BLAKE2/ref/blake2b-ref.c
        ####
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser_impl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/fil_utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser_raw_bytes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/crypto_helper.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/crypto_test.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/base32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/evm/parser_impl_evm_specific.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/evm/parser_invoke_evm.c

        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/parser_impl_evm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/parser_evm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/rlp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/uint256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/evm_erc20.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm/evm_utils.c
        )

add_library(app_lib STATIC
        ${LIB_SRC}
        ${TINYCBOR_SRC}
        )

target_include_directories(app_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/BLAKE2/ref
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/evm
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/evm
        )

##############################################################
#  Fuzz Targets
if(ENABLE_FUZZING) # Fuzz Targets
    # Setup fuzzing directories
    setup_fuzz_directories()
    
    # Add fuzz targets using the common macro
    add_fuzz_target(parser_parse ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/parser_parse.cpp app_lib)
    add_fuzz_target(parser_eth_parser ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/parser_eth_parser.cpp app_lib)
    
else()
    # #############################################################
    # #############################################################
    # Tests
    file(GLOB_RECURSE TESTS_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)

    add_executable(unittests ${TESTS_SRC})
    target_include_directories(unittests PRIVATE
        ${gtest_SOURCE_DIR}/include
        ${gmock_SOURCE_DIR}/include
        ${CONAN_INCLUDE_DIRS_FMT}
        ${CONAN_INCLUDE_DIRS_JSONCPP}
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/BLAKE2/ref
        )

    target_link_libraries(unittests PRIVATE
        GTest::gtest_main
        app_lib
        fmt::fmt
        nlohmann_json::nlohmann_json)

    add_compile_definitions(TESTVECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/")
    add_test(NAME unittests COMMAND unittests)
    set_tests_properties(unittests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()