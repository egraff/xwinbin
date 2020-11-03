FROM ubuntu:focal

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common

RUN \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev g++ g++-multilib

RUN cd ~ && mkdir cmake-tmp
COPY ci/cirrus/*.gpg ~/cmake-tmp/

RUN \
  cd ~/cmake-tmp && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt.asc && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-Linux-x86_64.sh && \
  gpg --no-default-keyring --keyring ./2D2CEF1034921684.gpg --verify cmake-3.18.4-SHA-256.txt.asc cmake-3.18.4-SHA-256.txt && \
  sha256sum --ignore-missing --check cmake-3.18.4-SHA-256.txt && \
  chmod +x cmake-3.18.4-Linux-x86_64.sh && \
  cd /usr/local && \
  printf 'y\nn\n' | ~/cmake-tmp/cmake-3.18.4-Linux-x86_64.sh && \
  cd ~ && \
  rm -rf cmake-tmp

RUN \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y g++-9-multilib g++-10-multilib && \
  apt-get install -y g++-9 g++-10 && \
  apt-get install -y g++-9-aarch64-linux-gnu g++-10-aarch64-linux-gnu && \
  apt-get install -y g++-9-mips64-linux-gnuabi64 g++-10-mips64-linux-gnuabi64 && \
  apt-get install -y g++-9-powerpc64-linux-gnu g++-10-powerpc64-linux-gnu && \
  apt-get install -y clang-10 clang-11

RUN \
  apt-get install -y qemu qemu-utils qemu-user qemu-user-static binfmt-support
