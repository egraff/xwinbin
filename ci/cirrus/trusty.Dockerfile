FROM ubuntu:trusty
WORKDIR /root

RUN \
  apt-get update && \
  apt-get install -y wget software-properties-common

RUN \
  apt-get install -y libc6-dev-i386 build-essential libssl-dev

RUN mkdir -p /root/cmake-tmp
COPY ci/cirrus/*.gpg /root/cmake-tmp/

RUN \
  cd /root/cmake-tmp && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-SHA-256.txt.asc && \
  wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4-Linux-x86_64.sh && \
  gpgv --keyring ./2D2CEF1034921684.gpg cmake-3.18.4-SHA-256.txt.asc cmake-3.18.4-SHA-256.txt && \
  cat cmake-3.18.4-SHA-256.txt | grep "cmake-3.18.4-Linux-x86_64.sh" > cmake-SHA-256.txt && \
  sha256sum --check cmake-SHA-256.txt && \
  chmod +x cmake-3.18.4-Linux-x86_64.sh && \
  cd /usr/local && \
  printf 'y\nn\n' | /root/cmake-tmp/cmake-3.18.4-Linux-x86_64.sh && \
  cd /root && \
  rm -rf cmake-tmp

RUN \
  apt-add-repository -y "ppa:ubuntu-toolchain-r/test" && \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.4 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.5 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.6 main" | tee -a /etc/apt/sources.list >/dev/null && \
  echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.7 main" | tee -a /etc/apt/sources.list >/dev/null && \
  apt-get update && \
  apt-get install -y g++-4.4-multilib g++-4.6-multilib && \
  apt-get install -y g++-4.4 g++-4.6 && \
  apt-get install -y clang-3.4 clang-3.5 clang-3.6 clang-3.7
