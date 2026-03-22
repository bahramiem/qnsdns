cmake_minimum_required(VERSION 3.16)
project(dnstun LANGUAGES C)

# Bypassing Git entirely to prevent authentication prompts during dependency fetching.
set(CMAKE_DISABLE_FIND_PACKAGE_Git TRUE)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── libuv ────────────────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
  libuv
  URL https://dist.libuv.org/dist/v1.48.0/libuv-v1.48.0.tar.gz
)
FetchContent_Declare(
  zstd
  URL            https://github.com/facebook/zstd/archive/794ea1b0afca0f020f4e57b6732332231fb23c70.tar.gz
  SOURCE_SUBDIR  build/cmake
)
FetchContent_Declare(
  sodium
  URL            https://download.libsodium.org/libsodium/releases/libsodium-1.0.19-stable.tar.gz
)
# Note: libRaptorQ can be complex to FetchContent; using a simpler RFC 6330 header-only or basic C impl if possible.
# For now, I'll use a placeholder or FetchContent a known stable one.
FetchContent_Declare(
  lz4
  URL            https://github.com/lz4/lz4/archive/refs/tags/v1.9.4.tar.gz
  SOURCE_SUBDIR  build/cmake
)
FetchContent_Declare(
  raptorq
  URL            https://github.com/LucaFulchir/libRaptorQ/archive/a394b22af6e8fc742ce88eacf9af5343ecded9d7.tar.gz
)

# Ensure raptorq can find the lz4 headers/libs we just fetched.
FetchContent_GetProperties(lz4)
if(NOT lz4_POPULATED)
  FetchContent_Populate(lz4)
  add_subdirectory(${lz4_SOURCE_DIR}/build/cmake ${lz4_BINARY_DIR})
endif()
set(LZ4_ROOT ${lz4_SOURCE_DIR})

FetchContent_MakeAvailable(libuv zstd sodium raptorq)

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
target_link_libraries(dnstun-client uv libzstd_static sodium RaptorQ_static)
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
target_link_libraries(dnstun-server uv libzstd_static sodium RaptorQ_static)
if(WIN32)
    target_link_libraries(dnstun-server ws2_32 iphlpapi userenv)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS dnstun-client dnstun-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
