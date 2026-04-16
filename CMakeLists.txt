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
    # Force include compatibility header for all files on MSVC
    add_compile_options("/FI${CMAKE_CURRENT_SOURCE_DIR}/shared/msvc_compat.h")
    # Mask common warnings
    add_compile_options("/wd4057" "/wd4100" "/wd4127" "/wd4244" "/wd4267" "/wd4018" "/wd4146")
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
    # ── Windows: use vcpkg-provided packages ─────────────────────────────────
    # GitHub Windows runners ship vcpkg at $env:VCPKG_INSTALLATION_ROOT.
    # The CI passes -DCMAKE_TOOLCHAIN_FILE to activate vcpkg.
    # Packages needed: libuv libsodium zstd  (install via vcpkg before cmake)
    find_package(libuv     CONFIG QUIET)
    find_package(libsodium CONFIG QUIET)
    find_package(zstd      CONFIG QUIET)

    # ── Fallback to third_party versions if vcpkg is empty ──────────────────
    if(NOT libuv_FOUND)
        message(STATUS "vcpkg libuv not found, using third_party/libuv")
        set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        add_subdirectory(third_party/libuv EXCLUDE_FROM_ALL)
        set(UV_LIBRARIES uv_a)
        set(UV_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libuv/include")
    else()
        set(UV_LIBRARIES $<IF:$<TARGET_EXISTS:libuv::uv_a>,libuv::uv_a,libuv::uv>)
    endif()

    if(NOT libsodium_FOUND)
        message(STATUS "vcpkg libsodium not found, using third_party/libsodium")
        # libsodium third_party might need custom setup if it doesn't have a good CMake
        add_subdirectory(third_party/libsodium EXCLUDE_FROM_ALL)
        set(SODIUM_LIBRARIES sodium)
    else()
        find_package(unofficial-sodium CONFIG QUIET)
        if(unofficial-sodium_FOUND)
            set(SODIUM_LIBRARIES unofficial-sodium::sodium)
        else()
            set(SODIUM_LIBRARIES sodium)
        endif()
    endif()

    if(NOT zstd_FOUND)
        message(STATUS "vcpkg zstd not found, using third_party/zstd")
        set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_STATIC   ON  CACHE BOOL "" FORCE)
        add_subdirectory(third_party/zstd/build/cmake EXCLUDE_FROM_ALL)
        set(ZSTD_LIBRARIES libzstd_static)
    else()
        set(ZSTD_LIBRARIES $<IF:$<TARGET_EXISTS:zstd::libzstd_static>,zstd::libzstd_static,zstd::libzstd_shared>)
    endif()

    set(ZSTD_LIBRARIES ${ZSTD_LIBRARIES})

    set(EIGEN3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libRaptorQ/external/eigen3")
    add_subdirectory(third_party/libRaptorQ EXCLUDE_FROM_ALL)
    set(RAPTORQ_LIBRARIES RaptorQ_Static)

    # vcpkg puts headers in standard places; find_package sets the import targets
    set(EXTRA_INCLUDES
        ${UV_INCLUDE_DIRS}
        ${SODIUM_INCLUDE_DIRS}
        ${ZSTD_INCLUDE_DIRS}
        third_party/libRaptorQ/src
    )

    set(PLATFORM_LINK_LIBS "")  # stdc++/m not used on MSVC

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
# ── Shared SPCDNS codec sources ───────────────────────────────────────────────
set(SPCDNS_SOURCES
    third_party/spcdns/codec.c
    third_party/spcdns/mappings.c
    third_party/spcdns/output.c
)

# ── Shared tunnel sources ─────────────────────────────────────────────────────
set(SHARED_SOURCES
    shared/config.c
    shared/base32.c
    shared/resolver_pool.c
    shared/tui.c
    shared/codec.c
    shared/mgmt.c
)

# ── Core Settings ─────────────────────────────────────────────────────────────
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Options ───────────────────────────────────────────────────────────────────
option(BUILD_SERVER "Build the tunnel server" ON)

# ── Client ────────────────────────────────────────────────────────────────────
set(CLIENT_SOURCES
    client/main.c
    client/session/session.c
    client/socks5/proxy.c
    client/resolver/probe.c
    client/resolver/mtu.c
    client/resolver/init.c
    client/aggregation/packet.c
    client/debug/packet.c
    client/tui/callbacks.c
    client/dns/query.c
)

add_executable(dnstun-client
    ${CLIENT_SOURCES}
    ${SPCDNS_SOURCES}
    ${SHARED_SOURCES}
)
target_include_directories(dnstun-client PRIVATE . shared third_party/spcdns ${EXTRA_INCLUDES})
target_link_libraries(dnstun-client
    ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES}
    ${RAPTORQ_LIBRARIES} ${PLATFORM_LINK_LIBS}
)
set_target_properties(dnstun-client PROPERTIES LINKER_LANGUAGE CXX)

if(WIN32)
    target_link_libraries(dnstun-client ws2_32 iphlpapi userenv)
endif()

# ── Server ────────────────────────────────────────────────────────────────────
if(BUILD_SERVER)
    set(SERVER_SOURCES
        server/main.c
        server/session/session.c
        server/swarm/swarm.c
        server/dns/protocol.c
        server/tui/callbacks.c
    )

    add_executable(dnstun-server
        ${SERVER_SOURCES}
        ${SPCDNS_SOURCES}
        ${SHARED_SOURCES}
    )
    target_include_directories(dnstun-server PRIVATE . shared third_party/spcdns ${EXTRA_INCLUDES})
    target_link_libraries(dnstun-server
        ${UV_LIBRARIES} ${ZSTD_LIBRARIES} ${SODIUM_LIBRARIES}
        ${RAPTORQ_LIBRARIES} ${PLATFORM_LINK_LIBS}
    )
    set_target_properties(dnstun-server PROPERTIES LINKER_LANGUAGE CXX)
    
    if(WIN32)
        target_link_libraries(dnstun-server ws2_32 iphlpapi userenv)
    endif()
endif()

# ── Standalone TUI ───────────────────────────────────────────────────────────
# Note: Building standalone TUI requires fixing Windows SDK include order issues
option(BUILD_STANDALONE_TUI "Build standalone TUI executable (connects to core via socket)" OFF)
if(BUILD_STANDALONE_TUI)
    add_subdirectory(tui-standalone)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS dnstun-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(BUILD_SERVER)
    install(TARGETS dnstun-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
