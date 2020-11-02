FROM ubuntu:bionic

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common

RUN \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-5.0 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-6.0 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev && \
  apt-get install -y g++-5-multilib g++-6-multilib g++-7-multilib g++-8-multilib && \
  apt-get install -y g++-5 g++-6 g++-7 g++-8 && \
  apt-get install -y g++-5-aarch64-linux-gnu g++-6-aarch64-linux-gnu g++-7-aarch64-linux-gnu g++-8-aarch64-linux-gnu && \
  apt-get install -y g++-5-mips64-linux-gnuabi64 g++-6-mips64-linux-gnuabi64 g++-7-mips64-linux-gnuabi64 g++-8-mips64-linux-gnuabi64 && \
  apt-get install -y g++-5-powerpc64-linux-gnuabi64 g++-6-powerpc64-linux-gnuabi64 g++-7-powerpc64-linux-gnuabi64 g++-8-powerpc64-linux-gnuabi64 && \
  apt-get install -y clang-5.0 clang-6.0 clang-7 clang-8 clang-9

RUN \
  mkdir cmake-src && \
  cd cmake-src && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz && \
  tar -xf cmake-3.18.4.tar.gz && \
  cd cmake-3.18.4 && \
  CXX="g++-8" ./bootstrap && \
  make && \
  make install && \
  cd ../.. && \
  rm -rf cmake-src
