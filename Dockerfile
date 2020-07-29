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

# Install Python Anaconda3
RUN echo 'export PATH=/opt/conda/bin:$PATH' > /etc/profile.d/conda.sh && \
    wget --quiet https://repo.continuum.io/archive/Anaconda3-5.3.1-Linux-x86_64.sh -O ~/anaconda.sh && \
    /bin/bash ~/anaconda.sh -b -p /opt/conda && \
    rm ~/anaconda.sh
ENV PATH /opt/conda/bin:$PATH

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
RUN wget https://github.com/souffle-lang/souffle/releases/download/1.7.1/souffle_1.7.1-1_amd64.deb -O /tmp/souffle.deb &&\
    gdebi --n /tmp/souffle.deb


# Souffle plugins
RUN wget https://github.com/yanniss/souffle-num-addon/archive/master.zip -O /tmp/souffle-num-addon.zip
RUN cd /tmp && unzip souffle-num-addon.zip
RUN cd /tmp/souffle-num-addon && make && mv libsoufflenum.so /usr/lib/libfunctors.so
RUN rm -rf /tmp/souffle-num-addon*

# Dependencies for Gigahorse output viz
RUN apt-get update && apt-get install -y graphviz
RUN conda install -c anaconda pydot
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
MKDIR /home/reviewer/gigahorse-toolchain
COPY * /home/reviewer/gigahorse-toolchain

# Install Python packages needed for Jupyter notebook
USER root
WORKDIR /tmp
RUN pip install --upgrade pip
RUN pip install numpy pandas py-solc-x statsd docopt web3

USER reviewer
WORKDIR /home/reviewer
RUN echo "export PATH=/opt/conda/bin:\$PATH" >> /home/reviewer/.bashrc  && \
    echo "export HOME=/home/reviewer" >> /home/reviewer/.bashrc


# Start reviewer user in logic subdir ready to run Gigahorse
EXPOSE 8888
USER reviewer
WORKDIR /home/reviewer/gigahorse-toolchain/logic
