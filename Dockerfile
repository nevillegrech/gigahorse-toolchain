FROM ubuntu:21.10

ENV EDITOR vim
ENV TERM xterm-256color
ENV DEBIAN_FRONTEND=noninteractive

# For initial config, use root user with files placed in /tmp
USER root

# Install some essentials
RUN apt-get update && apt-get install -y \
    build-essential \
    libboost-all-dev \
    wget \
    curl \
    vim-nox \
    tzdata \
    less \
    unzip \
    git

# Use UTC timezone
RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime
RUN dpkg-reconfigure --frontend noninteractive tzdata

# Install python3
RUN apt-get install python3-dev python3-pip -y

# Install souffle dependencies
RUN apt-get install -y \
    bison \
    clang \
    cmake \
    doxygen \
    flex \
    g++ \
    git \
    libtinfo-dev \
    libffi-dev \
    libncurses5-dev \
    libsqlite3-dev \
    make \
    mcpp \
    python \
    sqlite \
    zlib1g-dev \
    libffi-dev \
    parallel \
 && rm -rf /var/lib/apt/lists/*

# Clone souffle, checkout to the latest supported version and make
RUN git clone https://github.com/souffle-lang/souffle.git
RUN cd souffle && \
    git checkout 2.0.2 && \
    ./bootstrap && \
    ./configure && \
    make -j8 && \
    make install

# Dependencies for Gigahorse output viz
RUN apt-get update && apt-get install -y graphviz
RUN apt-get update && apt-get install -y libssl-dev

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install pydot

# Set up a non-root 'gigahorse' user
RUN groupadd -r gigahorse && useradd -ms /bin/bash -g gigahorse gigahorse

RUN mkdir -p /opt/gigahorse/gigahorse-toolchain

# Copy gigahorse project root
COPY . /opt/gigahorse/gigahorse-toolchain/

RUN chown -R gigahorse:gigahorse /opt/gigahorse
RUN chmod -R o+rwx /opt/gigahorse

# Switch to new 'gigahorse' user context
USER gigahorse

WORKDIR /opt/gigahorse/gigahorse-toolchain

# Souffle-addon bare-minimum make
RUN cd souffle-addon && make libsoufflenum.so

CMD ["-h"]
ENTRYPOINT ["/opt/gigahorse/gigahorse-toolchain/gigahorse.py"]
