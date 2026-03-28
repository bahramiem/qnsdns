cmake_minimum_required(VERSION 3.16)
project(dnstun-tui LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find libuv (compatible with root project logic)
if(NOT TARGET libuv::uv AND NOT TARGET libuv::uv_a AND NOT UV_LIBRARIES)
    if(UNIX AND NOT APPLE)
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(UV REQUIRED libuv)
        set(UV_LINK_LIBS ${UV_LIBRARIES})
        set(UV_INC_DIRS ${UV_INCLUDE_DIRS})
    else()
        find_package(libuv CONFIG REQUIRED)
        set(UV_LINK_LIBS $<IF:$<TARGET_EXISTS:libuv::uv_a>,libuv::uv_a,libuv::uv>)
        set(UV_INC_DIRS "")
    endif()
else()
    # Inherit from parent if available
    set(UV_LINK_LIBS ${UV_LIBRARIES})
    set(UV_INC_DIRS ${EXTRA_INCLUDES})
endif()

add_executable(dnstun-tui
    main.c
    mgmt_client.c
    renderer.c
)

target_include_directories(dnstun-tui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${UV_INC_DIRS}
)

target_link_libraries(dnstun-tui PRIVATE
    ${UV_LINK_LIBS}
)
