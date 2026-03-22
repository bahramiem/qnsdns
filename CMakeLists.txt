cmake_minimum_required(VERSION 3.16)
project(dnstun LANGUAGES C CXX)

# Bypassing Git entirely to prevent authentication prompts during dependency fetching.
set(CMAKE_DISABLE_FIND_PACKAGE_Git TRUE)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(UNIX AND NOT APPLE)
    # ── Linux System Dependencies ──────────────────────────────────────────
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(UV REQUIRED libuv)
    pkg_check_modules(ZSTD REQUIRED libzstd)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    # liblz4 is still useful for our own code, but libRaptorQ must use its
    # OWN bundled LZ4 to avoid streaming-API linker errors with system lz4.

    set(UV_LIBRARIES ${UV_LIBRARIES})
    set(ZSTD_LIBRARIES ${ZSTD_LIBRARIES})
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES})

    # libRaptorQ (Vendored) — force bundled LZ4 so streaming symbols are present
    set(LTO OFF CACHE BOOL "" FORCE)
    set(PROFILING OFF CACHE BOOL "" FORCE)
    set(USE_LZ4 ON CACHE BOOL "" FORCE)
    set(RQ_LZ4_USE_OWN ON CACHE BOOL "" FORCE)  # bundled LZ4 inside libRaptorQ
    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)

    set(EXTRA_INCLUDES
        ${UV_INCLUDE_DIRS}
        ${ZSTD_INCLUDE_DIRS}
        ${SODIUM_INCLUDE_DIRS}
        third_party/libRaptorQ/src
        third_party/libRaptorQ/external/lz4/lib
    )
else()
    # ── Vendored Dependencies ─────────────────────────────────────────────
    # libuv
    add_subdirectory(third_party/libuv EXCLUDE_FROM_ALL)
    # zstd
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/zstd/build/cmake EXCLUDE_FROM_ALL)
    # lz4
    set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/lz4/build/cmake EXCLUDE_FROM_ALL)
    # sodium 
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/CMakeLists.txt")
        add_subdirectory(third_party/libsodium EXCLUDE_FROM_ALL)
        set(SODIUM_LIBRARIES sodium)
    else()
        find_package(PkgConfig QUIET)
        pkg_check_modules(SODIUM libsodium)
    endif()
    # libRaptorQ
    set(LTO OFF CACHE BOOL "" FORCE)
    set(PROFILING OFF CACHE BOOL "" FORCE)
    set(LZ4_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4")
    set(EIGEN3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libRaptorQ/external/eigen3")
    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)

    set(UV_LIBRARIES uv_a)
    set(ZSTD_LIBRARIES libzstd_static)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)
    
    set(EXTRA_INCLUDES 
        third_party/libuv/include
        third_party/zstd/lib
        third_party/lz4/lib
        third_party/libsodium/src/libsodium/include
        third_party/libsodium/src/libsodium/include/sodium
        third_party/libRaptorQ/src
    )
endif()

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

# ── Core Settings ─────────────────────────────────────────────────────────────
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Client ────────────────────────────────────────────────────────────────────
add_executable(dnstun-client
    client/main.c
    ${SPCDNS_SOURCES}
    ${SHARED_SOURCES}
)
target_include_directories(dnstun-client PRIVATE . shared SPCDNS ${EXTRA_INCLUDES})
target_link_libraries(dnstun-client ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES} ${RAPTORQ_LIBRARIES} m stdc++ ${LZ4_LIBRARIES})
set_target_properties(dnstun-client PROPERTIES LINKER_LANGUAGE CXX)

if(WIN32)
    target_link_libraries(dnstun-client ws2_32 iphlpapi userenv)
endif()

# ── Server ────────────────────────────────────────────────────────────────────
add_executable(dnstun-server
    server/main.c
    ${SPCDNS_SOURCES}
    ${SHARED_SOURCES}
)
target_include_directories(dnstun-server PRIVATE . shared SPCDNS ${EXTRA_INCLUDES})
target_link_libraries(dnstun-server ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES} ${RAPTORQ_LIBRARIES} m stdc++ ${LZ4_LIBRARIES})
set_target_properties(dnstun-server PROPERTIES LINKER_LANGUAGE CXX)

if(WIN32)
    target_link_libraries(dnstun-server ws2_32 iphlpapi userenv)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS dnstun-client dnstun-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
