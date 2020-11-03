set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips64)

set(cross_prefix mips64-linux-gnuabi64-)
if(DEFINED ENV{CROSS_PREFIX})
  set(cross_prefix $ENV{CROSS_PREFIX})
endif()

set(cross_suffix "")
if(DEFINED ENV{CROSS_SUFFIX})
  set(cross_suffix $ENV{CROSS_SUFFIX})
endif()

if(NOT DEFINED(CMAKE_C_COMPILER))
  set(CMAKE_C_COMPILER ${cross_prefix}gcc${cross_suffix})
endif()

if(NOT DEFINED(CMAKE_CXX_COMPILER))
  set(CMAKE_CXX_COMPILER ${cross_prefix}g++${cross_suffix})
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_CROSSCOMPILING_EMULATOR "qemu-mips64 -L /usr/mips64-linux-gnuabi64")
