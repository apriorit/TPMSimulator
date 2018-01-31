cmake_minimum_required(VERSION 3.5)

project(TPM)

file(GLOB_RECURSE PROVIDER_SOURCES "*.h" "*.c" "../OsslCryptoEngine/*.c" "../platform/*.c")

add_library(TPM STATIC ${PROVIDER_SOURCES})

find_package(OpenSSL REQUIRED)
target_link_libraries(TPM OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(TPM PUBLIC
    ./include
    ./include/prototypes
    ../include
    ../lib
    ../platform/include/prototypes
    ../platform/include
    )

if(MSVC)
    target_compile_options(TPM PRIVATE /wd4201 /wd4013 /wd4018 /wd4244 /wd4456 /wd4459 /wd4715)
endif()