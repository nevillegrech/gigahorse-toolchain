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

# ---- Python toolchain via uv (Astral) ----
# Install the uv binary and provision a managed CPython 3.13 into a shared,
# world-readable prefix so the non-root user in downstream images can use it.
# The project's own dependencies (pytest, mypy, ...) come from pyproject.toml /
# uv.lock via `uv sync` in the image or CI step that checks out the repository.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv python install 3.13 && chmod -R a+rX /opt/uv

RUN souffle --version
RUN uv --version && uv run --no-project --python 3.13 python --version