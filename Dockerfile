FROM ubuntu:18.04

ENV EDITOR vim
ENV TERM xterm-256color
ENV DEBIAN_FRONTEND=noninteractive

# For initial config, use root user with files placed in /tmp
USER root
WORKDIR /tmp

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
    git\
 && rm -rf /var/lib/apt/lists/*

# Use UTC timezone
RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime
RUN dpkg-reconfigure --frontend noninteractive tzdata

# Install Python 3.8
RUN apt-get update && apt-get install python3.8-dev python3-pip -y

# Install Souffle dependencies and Souffle
RUN apt-get update && apt-get install -y \
    libmcpp0 \
    libncurses5-dev \
    libsqlite3-dev \
    libtinfo-dev \
    mcpp \
    zlib1g-dev \
    libffi-dev \
    parallel


# install souffle
RUN wget https://github.com/souffle-lang/souffle/releases/download/2.0.2/souffle_2.0.2-1_amd64.deb -O /tmp/souffle.deb
RUN dpkg -i /tmp/souffle.deb
RUN apt-get install -f -y


# Souffle plugins
RUN wget https://github.com/plast-lab/souffle-addon/archive/master.zip -O /tmp/souffle-addon.zip
RUN cd /tmp && unzip souffle-addon.zip
RUN cd /tmp/souffle-addon-master && make && mv libsoufflenum.so /usr/lib/libfunctors.so
RUN rm -rf /tmp/souffle-addon*

# Dependencies for Gigahorse output viz
RUN apt-get update && apt-get install -y graphviz
RUN apt-get update && apt-get install -y libssl-dev

RUN python3.8 -m pip install --upgrade pip
RUN python3.8 -m pip install pydot

# Make python3 point to python3.8
RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.8 /usr/bin/python3

# Set up a non-root 'gigahorse' user
RUN groupadd -r gigahorse && useradd -ms /bin/bash -g gigahorse gigahorse

RUN mkdir -p /opt/gigahorse/gigahorse-toolchain
RUN chown -R gigahorse:gigahorse /opt/gigahorse

# Switch to new 'gigahorse' user context
USER gigahorse

# Copy gigahorse project root
COPY . /opt/gigahorse/gigahorse-toolchain/

WORKDIR /opt/gigahorse/gigahorse-toolchain

CMD ["-h"]
ENTRYPOINT ["/opt/gigahorse/gigahorse-toolchain/gigahorse.py"]