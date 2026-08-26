FROM ubuntu:22.04

USER root

ENV DEBIAN_FRONTEND=noninteractive


# Install some essentials
RUN apt-get update && apt-get upgrade -y && apt-get install -y libboost-all-dev 

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
    sqlite \
    zlib1g-dev \
    libffi-dev \
    libffi7 \
    parallel \
 && rm -rf /var/lib/apt/lists/*

COPY ./docker/mac/souffle_2.2-1_arm64.deb /tmp/souffle.deb
RUN dpkg -i /tmp/souffle.deb
RUN apt-get install -f -y

# Dependencies for Gigahorse output viz
RUN apt-get update && apt-get install -y graphviz
RUN apt-get update && apt-get install -y libssl-dev

# ---- Python toolchain via uv (Astral) ----
# Install the uv binary and provision a managed CPython 3.13 into a shared,
# world-readable prefix so the non-root user below can use it.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv python install 3.13 && chmod -R a+rX /opt/uv

# Set up a non-root 'gigahorse' user
RUN groupadd -r gigahorse && useradd -ms /bin/bash -g gigahorse gigahorse

RUN mkdir -p /opt/gigahorse/gigahorse-toolchain

# Copy gigahorse project root
COPY . /opt/gigahorse/gigahorse-toolchain/

WORKDIR /opt/gigahorse/gigahorse-toolchain

# Create the project venv (managed CPython 3.13) with the graphviz/dot output
# visualisation extra (pydot) that this image ships. --no-dev keeps the test/type
# tooling out of the image.
RUN uv sync --frozen --no-dev --extra viz

# Put the project venv first on PATH so the scripts' `#!/usr/bin/env python3` shebang
# resolves to the uv-managed Python 3.13 interpreter.
ENV PATH="/opt/gigahorse/gigahorse-toolchain/.venv/bin:${PATH}"

RUN chown -R gigahorse:gigahorse /opt/gigahorse
RUN chmod -R o+rwx /opt/gigahorse

# Switch to new 'gigahorse' user context
USER gigahorse

# Souffle-addon bare-minimum make
RUN cd /opt/gigahorse/gigahorse-toolchain/souffle-addon && make libsoufflenum.so

CMD ["-h"]
ENTRYPOINT ["/opt/gigahorse/gigahorse-toolchain/gigahorse.py"]
