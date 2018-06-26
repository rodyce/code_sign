cmake_minimum_required (VERSION 2.8)
project (coin_sign)

set (COIN_SIGN coin_sign)

include(FindPkgConfig)

include_directories (
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/secp256k1/include
    ${CMAKE_SOURCE_DIR}/univalue
)

file(GLOB SOURCES ${CMAKE_SOURCE_DIR}/*.cpp)
file(GLOB CRYPTO_SOURCES ${CMAKE_SOURCE_DIR}/crypto/*.cpp)
file(GLOB PRIMITIVES_SOURCES ${CMAKE_SOURCE_DIR}/primitives/*.cpp)
file(GLOB SCRIPT_SOURCES ${CMAKE_SOURCE_DIR}/script/*.cpp)
file(GLOB SUPPORT_SOURCES ${CMAKE_SOURCE_DIR}/support/*.cpp)
file(GLOB UNIVALUE_SOURCES ${CMAKE_SOURCE_DIR}/univalue/*.cpp)

set (SOURCE
    ${SOURCES}
    ${CRYPTO_SOURCES}
    ${PRIMITIVES_SOURCES}
    ${SCRIPT_SOURCES}
    ${SUPPORT_SOURCES}
    ${UNIVALUE_SOURCES}
)

add_compile_options(-std=c++11 -Wall -Werror -ggdb -g3 -rdynamic -O0)
add_definitions(
    -DHAVE_DECL_HTOBE16 -DHAVE_DECL_HTOLE16 -DHAVE_DECL_BE16TOH -DHAVE_DECL_LE16TOH
    -DHAVE_DECL_HTOBE32 -DHAVE_DECL_HTOLE32 -DHAVE_DECL_BE32TOH
    -DHAVE_DECL_LE32TOH -DHAVE_DECL_HTOBE64 -DHAVE_DECL_HTOLE64
    -DHAVE_DECL_BE64TOH -DHAVE_DECL_LE64TOH
)

add_executable(${COIN_SIGN}
    ${SOURCE}
)
