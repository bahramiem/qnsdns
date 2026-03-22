@echo off
set "PATH=C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\CMake_64\bin;%PATH%"
cmake.exe --build . > build_out.txt 2>&1
echo Done building.
