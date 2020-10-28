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
  apt-get install -y cmake libc6-dev-i386 && \
  apt-get install -y g++-4.7-multilib g++-4.8-multilib g++-4.9-multilib && \
  apt-get install -y g++-4.7 g++-4.8 g++-4.9 && \
  apt-get install -y clang-3.8 clang-3.9 clang-4.0
