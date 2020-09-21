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

# Install tini (https://github.com/krallin/tini)
RUN apt-get install -y curl grep sed dpkg && \
    TINI_VERSION=`curl https://github.com/krallin/tini/releases/latest | grep -o "/v.*\"" | sed 's:^..\(.*\).$:\1:'` && \
    curl -L "https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini_${TINI_VERSION}.deb" > tini.deb && \
    dpkg -i tini.deb && \
    rm tini.deb && \
    apt-get clean

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
RUN wget https://github.com/souffle-lang/souffle/releases/download/2.0.1/souffle_2.0.1-1_amd64.deb -O /tmp/souffle.deb
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

# When container is launched, tini will launch a bash shell
ENTRYPOINT [ "/usr/bin/tini", "--" ]
CMD [ "/bin/bash" ]

# Set up a non-root user for the reviewer
RUN groupadd -r reviewer && useradd -ms /bin/bash -g reviewer reviewer

# Switch to new 'reviewer' user context
USER reviewer
WORKDIR /home/reviewer

# Copy our artifacts into reviewer's home dir
RUN mkdir /home/reviewer/gigahorse-toolchain
COPY . /home/reviewer/gigahorse-toolchain/

# Install Python packages needed for Jupyter notebook
USER root
WORKDIR /tmp
RUN python3.8 -m pip install --upgrade pip
RUN python3.8 -m pip install pydot

# Make python3 point to python3.8
RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.8 /usr/bin/python3

# Make reviewer the owner of everything under their home
RUN chown -R reviewer:reviewer ~reviewer

USER reviewer
WORKDIR /home/reviewer
RUN echo "export HOME=/home/reviewer" >> /home/reviewer/.bashrc


# Start reviewer user in logic subdir ready to run Gigahorse
EXPOSE 8888
USER reviewer
WORKDIR /home/reviewer/gigahorse-toolchain/logic
