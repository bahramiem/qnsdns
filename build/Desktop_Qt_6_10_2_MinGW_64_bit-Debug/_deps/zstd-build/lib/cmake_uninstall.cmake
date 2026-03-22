 
if(NOT EXISTS "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/install_manifest.txt")
  message(FATAL_ERROR "Cannot find install manifest: D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/install_manifest.txt")
endif()

file(READ "D:/qns/qnsdns/build/Desktop_Qt_6_10_2_MinGW_64_bit-Debug/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
  message(STATUS "Uninstalling $ENV{DESTDIR}${file}")
  if(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    exec_program(
      "C:/Qt/Tools/CMake_64/bin/cmake.exe" ARGS "-E remove \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    if(NOT "${rm_retval}" STREQUAL 0)
      message(FATAL_ERROR "Problem when removing $ENV{DESTDIR}${file}")
    endif()
  else()
    message(STATUS "File $ENV{DESTDIR}${file} does not exist.")
  endif()
endforeach()
