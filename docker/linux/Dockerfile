FROM ghcr.io/nevillegrech/gigahorse-toolchain-deps-souffle24:latest

USER root

ENV DEBIAN_FRONTEND=noninteractive

# Set up a non-root 'gigahorse' user
RUN groupadd -r gigahorse && useradd -ms /bin/bash -g gigahorse gigahorse

RUN mkdir -p /opt/gigahorse/gigahorse-toolchain

# Copy gigahorse project root
COPY . /opt/gigahorse/gigahorse-toolchain/

WORKDIR /opt/gigahorse/gigahorse-toolchain

# uv + a managed CPython 3.13 are already provided by the deps base image; (re-)install
# them here as well so this image also builds correctly against an older base image that
# predates the uv toolchain. Idempotent when the base already ships uv.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv python install 3.13 && chmod -R a+rX /opt/uv

# Create the project virtual environment from the committed uv.lock. The core toolchain
# has no third-party runtime dependencies, so this just pins the interpreter; --no-dev
# keeps the test/type-checker tooling out of the runtime image.
RUN uv sync --frozen --no-dev

# Put the project venv first on PATH so `#!/usr/bin/env python3` (in gigahorse.py and the
# other entrypoint scripts) resolves to the uv-managed Python 3.13 interpreter.
ENV PATH="/opt/gigahorse/gigahorse-toolchain/.venv/bin:${PATH}"

RUN chown -R gigahorse:gigahorse /opt/gigahorse
RUN chmod -R o+rwx /opt/gigahorse

# Switch to new 'gigahorse' user context
USER gigahorse

# Souffle-addon bare-minimum make
RUN cd /opt/gigahorse/gigahorse-toolchain/souffle-addon && make libsoufflenum.so

CMD ["-h"]
ENTRYPOINT ["/opt/gigahorse/gigahorse-toolchain/gigahorse.py"]

# Commenting it out, to be uncommented and to debug and run as interactive container
# # Start gigahorse user in logic subdir ready to run Gigahorse
# EXPOSE 8888
# USER gigahorse
# WORKDIR /opt/gigahorse/gigahorse-toolchain