cmake_minimum_required(VERSION 3.10)
project(sodium LANGUAGES C)

# libsodium is complex to build fully with a simple CMake file, 
# but for most features we just need the core sources.
# This is a simplified wrapper.

file(GLOB_RECURSE SODIUM_SOURCES 
    "src/libsodium/*.c"
)

# Exclude some known problematic files if necessary
# list(REMOVE_ITEM SODIUM_SOURCES ...)

add_library(sodium STATIC ${SODIUM_SOURCES})

target_include_directories(sodium PUBLIC 
    "src/libsodium/include"
    "src/libsodium/include/sodium"
)

target_compile_definitions(sodium PRIVATE 
    HAVE_CONFIG_H 
    CONFIG_H
    PACKAGE_NAME="libsodium"
    PACKAGE_VERSION="1.0.19"
)

# Note: In a real environment, you'd run ./configure once to generate a proper config.h
# For now, we assume a basic build is sufficient for the DNS tunnel's needs.

if(MSVC)
    target_compile_definitions(sodium PRIVATE HAVE_CONFIG_H)
endif()
