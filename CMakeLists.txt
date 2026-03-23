cmake_minimum_required(VERSION 3.16)
project(dnstun LANGUAGES C CXX)

# Bypassing Git entirely to prevent authentication prompts during dependency fetching.
set(CMAKE_DISABLE_FIND_PACKAGE_Git TRUE)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# MSVC: use static CRT (/MT) to match vcpkg x64-windows-static packages.
# Without this, MSVC defaults to /MD (dynamic CRT), causing LNK4098.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ── Common libRaptorQ options (LZ4 disabled: only used for optional caching) ──
set(LTO       OFF CACHE BOOL "" FORCE)
set(PROFILING OFF CACHE BOOL "" FORCE)
set(USE_LZ4   OFF CACHE BOOL "" FORCE)
set(RQ_LZ4_USE_OWN OFF CACHE BOOL "" FORCE)

if(UNIX AND NOT APPLE)
    # ── Linux: use system packages (installed via apt) ────────────────────────
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(UV     REQUIRED libuv)
    pkg_check_modules(ZSTD   REQUIRED libzstd)
    pkg_check_modules(SODIUM REQUIRED libsodium)

    set(UV_LIBRARIES     ${UV_LIBRARIES})
    set(ZSTD_LIBRARIES   ${ZSTD_LIBRARIES})
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES})

    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)

    set(EXTRA_INCLUDES
        ${UV_INCLUDE_DIRS}
        ${ZSTD_INCLUDE_DIRS}
        ${SODIUM_INCLUDE_DIRS}
        third_party/libRaptorQ/src
    )

    # Linux-only link extras
    set(PLATFORM_LINK_LIBS m stdc++)

elseif(WIN32)
    # ── Windows: try vcpkg first, then fallback to vendored fallback ─────────
    # Packages needed: libuv libsodium zstd (install via vcpkg OR use third_party)
    
    find_package(libuv CONFIG QUIET)
    if(libuv_FOUND)
        set(UV_LIBRARIES $<IF:$<TARGET_EXISTS:libuv::uv_a>,libuv::uv_a,libuv::uv>)
        set(EXTRA_UV_INCLUDES "")
    else()
        message(STATUS "libuv not found via CONFIG; using vendored third_party/libuv")
        add_subdirectory(third_party/libuv EXCLUDE_FROM_ALL)
        set(UV_LIBRARIES uv_a)
        set(EXTRA_UV_INCLUDES third_party/libuv/include)
    endif()

    find_package(libsodium CONFIG QUIET)
    if(NOT libsodium_FOUND)
        find_package(unofficial-sodium CONFIG QUIET)
        if(unofficial-sodium_FOUND)
            set(SODIUM_LIBRARIES unofficial-sodium::sodium)
            set(EXTRA_SODIUM_INCLUDES "")
        elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/CMakeLists.txt")
            message(STATUS "libsodium not found; using vendored third_party/libsodium")
            add_subdirectory(third_party/libsodium EXCLUDE_FROM_ALL)
            set(SODIUM_LIBRARIES sodium)
            set(EXTRA_SODIUM_INCLUDES third_party/libsodium/src/libsodium/include third_party/libsodium/src/libsodium/include/sodium)
        endif()
    else()
        set(SODIUM_LIBRARIES sodium)
        set(EXTRA_SODIUM_INCLUDES "")
    endif()

    find_package(zstd CONFIG QUIET)
    if(zstd_FOUND)
        set(ZSTD_LIBRARIES $<IF:$<TARGET_EXISTS:zstd::libzstd_static>,zstd::libzstd_static,zstd::libzstd_shared>)
        set(EXTRA_ZSTD_INCLUDES "")
    else()
        message(STATUS "zstd not found via CONFIG; using vendored third_party/zstd")
        set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
        add_subdirectory(third_party/zstd/build/cmake EXCLUDE_FROM_ALL)
        set(ZSTD_LIBRARIES libzstd_static)
        set(EXTRA_ZSTD_INCLUDES third_party/zstd/lib)
    endif()

    set(EIGEN3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libRaptorQ/external/eigen3")
    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)

    set(EXTRA_INCLUDES
        ${EXTRA_UV_INCLUDES}
        ${EXTRA_SODIUM_INCLUDES}
        ${EXTRA_ZSTD_INCLUDES}
        third_party/libRaptorQ/src
    )

    set(PLATFORM_LINK_LIBS "")
else()
    # ── macOS / other: best-effort vendored fallback ──────────────────────────
    add_subdirectory(third_party/libuv EXCLUDE_FROM_ALL)
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/zstd/build/cmake EXCLUDE_FROM_ALL)

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/CMakeLists.txt")
        add_subdirectory(third_party/libsodium EXCLUDE_FROM_ALL)
        set(SODIUM_LIBRARIES sodium)
    endif()

    set(EIGEN3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libRaptorQ/external/eigen3")
    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)

    set(UV_LIBRARIES   uv_a)
    set(ZSTD_LIBRARIES libzstd_static)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)

    set(EXTRA_INCLUDES
        third_party/libuv/include
        third_party/zstd/lib
        third_party/libsodium/src/libsodium/include
        third_party/libsodium/src/libsodium/include/sodium
        third_party/libRaptorQ/src
    )
    set(PLATFORM_LINK_LIBS m stdc++)
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
target_link_libraries(dnstun-client
    ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES}
    ${RAPTORQ_LIBRARIES} ${PLATFORM_LINK_LIBS}
)
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
target_link_libraries(dnstun-server
    ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES}
    ${RAPTORQ_LIBRARIES} ${PLATFORM_LINK_LIBS}
)
set_target_properties(dnstun-server PROPERTIES LINKER_LANGUAGE CXX)

if(WIN32)
    target_link_libraries(dnstun-server ws2_32 iphlpapi userenv)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS dnstun-client dnstun-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
