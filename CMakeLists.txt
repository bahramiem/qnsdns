cmake_minimum_required(VERSION 3.16)
project(dnstun LANGUAGES C)

# Bypassing Git entirely to prevent authentication prompts during dependency fetching.
set(CMAKE_DISABLE_FIND_PACKAGE_Git TRUE)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── libuv ────────────────────────────────────────────────────────────────────
include(FetchContent)
# ── Dependencies ─────────────────────────────────────────────────────────────

# libuv
add_subdirectory(third_party/libuv EXCLUDE_FROM_ALL)

# zstd
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zstd/build/cmake EXCLUDE_FROM_ALL)

# lz4
set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/lz4/build/cmake EXCLUDE_FROM_ALL)

# sodium (Using a simple wrapper or assuming it has a CMakeLists.txt)
# If libsodium has no CMakeLists.txt, we'll need to add one or use a system-installed version.
# For now, let's try to add it if it exists.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/CMakeLists.txt")
    add_subdirectory(third_party/libsodium EXCLUDE_FROM_ALL)
else()
    # Fallback to system libsodium or add a custom wrapper here
    find_package(PkgConfig QUIET)
    pkg_check_modules(SODIUM libsodium)
endif()

# libRaptorQ
# Setup RaptorQ (disable LTO and PROFILING for stability during initial setup)
set(LTO OFF CACHE BOOL "" FORCE)
set(PROFILING OFF CACHE BOOL "" FORCE)
set(LZ4_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4")
set(EIGEN3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libRaptorQ/external/eigen3")
add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)

# Link targets
# Link targets
set(UV_LIBRARIES uv_a)
set(ZSTD_LIBRARIES libzstd_static)
set(SODIUM_LIBRARIES sodium)
set(RAPTORQ_LIBRARIES RaptorQ_Static)

# ── Shared SPCDNS codec sources ───────────────────────────────────────────────
set(SPCDNS_SOURCES
    SPCDNS/codec.c
    SPCDNS/mappings.c
    SPCDNS/output.c
)

# ── Shared tunnel sources ─────────────────────────────────────────────────────
set(SHARED_SOURCES
    shared/config.c
    shared/base32.c
    shared/resolver_pool.c
    shared/tui.c
    shared/codec.c
)

# ── Client ────────────────────────────────────────────────────────────────────
add_executable(dnstun-client
    client/main.c
    ${SPCDNS_SOURCES}
    ${SHARED_SOURCES}
)
target_include_directories(dnstun-client PRIVATE . shared SPCDNS)
target_link_libraries(dnstun-client ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES} ${RAPTORQ_LIBRARIES})
if(WIN32)
    target_link_libraries(dnstun-client ws2_32 iphlpapi userenv)
endif()

# ── Server ────────────────────────────────────────────────────────────────────
add_executable(dnstun-server
    server/main.c
    ${SPCDNS_SOURCES}
    ${SHARED_SOURCES}
)
target_include_directories(dnstun-server PRIVATE . shared SPCDNS)
target_link_libraries(dnstun-server ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES} ${RAPTORQ_LIBRARIES})
if(WIN32)
    target_link_libraries(dnstun-server ws2_32 iphlpapi userenv)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS dnstun-client dnstun-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
