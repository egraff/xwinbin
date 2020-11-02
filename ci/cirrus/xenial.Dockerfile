FROM ubuntu:xenial

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common apt-utils apt-transport-https

RUN \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.8 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-4.0 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev && \
  apt-get install -y g++-4.7-multilib g++-4.8-multilib g++-4.9-multilib && \
  apt-get install -y g++-4.7 g++-4.8 g++-4.9 && \
  apt-get install -y g++-4.8-aarch64-linux-gnu g++-4.9-aarch64-linux-gnu && \
  apt-get install -y clang-3.8 clang-3.9 clang-4.0

RUN \
  mkdir cmake-src && \
  cd cmake-src && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz && \
  tar -xf cmake-3.18.4.tar.gz && \
  cd cmake-3.18.4 && \
  CXX="g++-4.9" ./bootstrap && \
  make && \
  make install && \
  cd ../.. && \
  rm -rf cmake-src
