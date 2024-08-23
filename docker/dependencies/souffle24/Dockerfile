FROM ubuntu:22.04

USER root

ENV DEBIAN_FRONTEND=noninteractive

# Install some essentials
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    build-essential \
    libboost-all-dev \
    wget

# Install python3
RUN apt-get install python3-dev python3-pip -y

RUN apt install -y \
  bison \
  build-essential \
  clang \
  cmake \
  doxygen \
  flex \
  g++ \
  git \
  libffi-dev \
  libncurses5-dev \
  libsqlite3-dev \
  make \
  mcpp \
  sqlite \
  zlib1g-dev

RUN git clone https://github.com/souffle-lang/souffle
RUN cd souffle && git checkout 2.4.1 && cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr/local && cmake --build build --target install -j 2

RUN apt-get update && apt-get install -y libssl-dev
RUN apt-get update && apt-get install -y libz3-dev
RUN apt-get update && apt-get install -y z3

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install pytest

RUN souffle --version
RUN python3 --version