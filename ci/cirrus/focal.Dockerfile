FROM ubuntu:focal

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common

RUN \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev && \
  apt-get install -y g++-9-multilib g++-10-multilib && \
  apt-get install -y g++-9 g++-10 && \
  apt-get install -y clang-10 clang-11

RUN \
  mkdir cmake-src && \
  cd cmake-src && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz && \
  tar -xf cmake-3.18.4.tar.gz && \
  cd cmake-3.18.4 && \
  CXX="g++-10" ./bootstrap && \
  make && \
  make install && \
  cd ../.. && \
  rm -rf cmake-src
