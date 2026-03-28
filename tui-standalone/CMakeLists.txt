cmake_minimum_required(VERSION 3.16)
project(dnstun-tui LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find libuv
find_package(libuv CONFIG REQUIRED)

add_executable(dnstun-tui
    main.c
    mgmt_client.c
    renderer.c
)

target_include_directories(dnstun-tui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(dnstun-tui PRIVATE
    libuv::uv
)
