FROM ubuntu:trusty

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common

RUN \
  apt-add-repository -y "ppa:ubuntu-toolchain-r/test" && \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.4 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.5 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.6 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.7 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev && \
  apt-get install -y g++-4.4-multilib g++-4.6-multilib && \
  apt-get install -y g++-4.4 g++-4.6 && \
  apt-get install -y clang-3.4 clang-3.5 clang-3.6 clang-3.7

RUN \
  mkdir cmake-src && \
  cd cmake-src && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz && \
  tar -xf cmake-3.18.4.tar.gz && \
  cd cmake-3.18.4 && \
  CXX="clang++-3.7" ./bootstrap && \
  make && \
  make install && \
  cd ../.. && \
  rm -rf cmake-src
