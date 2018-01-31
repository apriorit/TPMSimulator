cmake_minimum_required(VERSION 3.5)

project(Simulator)

file(GLOB_RECURSE PROVIDER_SOURCES "*.h" "*.c")

add_executable(Simulator ${PROVIDER_SOURCES})

target_include_directories(Simulator PRIVATE include)
target_link_libraries(Simulator TPM)

if(WIN32)
    target_link_libraries(Simulator Ws2_32 Rpcrt4)
else()
    target_link_libraries(Simulator pthread)
endif()

if(MSVC)
    target_compile_options(Simulator PRIVATE /wd4702 /wd4245 /wd4189)
endif()