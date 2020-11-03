FROM ubuntu:xenial
WORKDIR /root

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common apt-utils apt-transport-https

RUN \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev g++ g++-multilib

RUN mkdir -p /root/cmake-tmp
COPY ci/cirrus/*.gpg /root/cmake-tmp/

RUN \
  cd /root/cmake-tmp && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt.asc && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-Linux-x86_64.sh && \
  gpgv --keyring ./2D2CEF1034921684.gpg cmake-3.18.4-SHA-256.txt.asc cmake-3.18.4-SHA-256.txt && \
  sha256sum --ignore-missing --check cmake-3.18.4-SHA-256.txt && \
  chmod +x cmake-3.18.4-Linux-x86_64.sh && \
  cd /usr/local && \
  printf 'y\nn\n' | /root/cmake-tmp/cmake-3.18.4-Linux-x86_64.sh && \
  cd /root && \
  rm -rf cmake-tmp

RUN \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.8 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-4.0 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y g++-4.7-multilib g++-4.8-multilib g++-4.9-multilib && \
  apt-get install -y g++-4.7 g++-4.8 g++-4.9 && \
  apt-get install -y g++-4.8-aarch64-linux-gnu g++-4.9-aarch64-linux-gnu && \
  apt-get install -y clang-3.8 clang-3.9 clang-4.0

RUN \
  apt-get install -y qemu qemu-utils qemu-user qemu-user-static binfmt-support
