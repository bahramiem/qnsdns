# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-src")
  file(MAKE_DIRECTORY "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-src")
endif()
file(MAKE_DIRECTORY
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-build"
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix"
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/tmp"
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp"
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/src"
  "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/_deps/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
