cmake_minimum_required (VERSION 2.8)
project (coin_sign)

set (COIN_SIGN coin_sign)

include(FindPkgConfig)
find_package(Boost 1.58.0 REQUIRED)

if (Boost_FOUND)
    message("Boost found")
else()
    message("Boost NOT found")
endif()

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
    ${CRYPTO_SOURCES}
    ${PRIMITIVES_SOURCES}
    ${SCRIPT_SOURCES}
    ${SUPPORT_SOURCES}
    ${UNIVALUE_SOURCES}
    ${SOURCES}
)

add_compile_options(-std=c++11 -Wall -Werror -ggdb -g3 -rdynamic -O0)
add_definitions(
    -DHAVE_DECL_HTOBE16 -DHAVE_DECL_HTOLE16 -DHAVE_DECL_BE16TOH
    -DHAVE_DECL_LE16TOH=1 -DHAVE_DECL_HTOBE32 -DHAVE_DECL_HTOLE32
    -DHAVE_DECL_BE32TOH -DHAVE_DECL_LE32TOH -DHAVE_DECL_HTOBE64
    -DHAVE_DECL_HTOLE64 -DHAVE_DECL_BE64TOH -DHAVE_DECL_LE64TOH
    -DHAVE_WORKING_BOOST_SLEEP_FOR
    -DHAVE_DECL_STRNLEN=1
    -DCOPYRIGHT_YEAR=2018
    -DCOPYRIGHT_HOLDERS="The Coin Sign developers"
    -DCOPYRIGHT_HOLDERS_SUBSTITUTION="Coin Sign"
)

add_executable(${COIN_SIGN}
    ${SOURCE}
)

target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})