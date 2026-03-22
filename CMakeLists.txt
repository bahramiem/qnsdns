cmake_minimum_required(VERSION 3.16)
project(dnstun LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── libuv ────────────────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
  libuv
  GIT_REPOSITORY https://github.com/libuv/libuv.git
  GIT_TAG        v1.48.0
)
FetchContent_Declare(
  zstd
  GIT_REPOSITORY https://github.com/facebook/zstd.git
  GIT_TAG        v1.5.6
  SOURCE_SUBDIR  build/cmake
)
FetchContent_Declare(
  sodium
  GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
  GIT_TAG        1.0.19
)
# Note: libRaptorQ can be complex to FetchContent; using a simpler RFC 6330 header-only or basic C impl if possible.
# For now, I'll use a placeholder or FetchContent a known stable one.
FetchContent_Declare(
  raptorq
  GIT_REPOSITORY https://github.com/c-m-m/libRaptorQ.git
  GIT_TAG        v1.1.0
)
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
