set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc64)

set(cross_suffix "")
if(DEFINED ENV{CROSS_SUFFIX})
  set(cross_suffix $ENV{CROSS_SUFFIX})
endif()

set(triple powerpc64-linux-gnu)
if(DEFINED ENV{CLANG_TRIPLE})
  set(triple $ENV{CLANG_TRIPLE})
endif()

if(NOT DEFINED(CMAKE_C_COMPILER))
  set(CMAKE_C_COMPILER clang${cross_suffix})
endif()

if(NOT DEFINED(CMAKE_CXX_COMPILER))
  set(CMAKE_CXX_COMPILER clang++${cross_suffix})
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-ppc64 -L /usr/powerpc64-linux-gnu")
