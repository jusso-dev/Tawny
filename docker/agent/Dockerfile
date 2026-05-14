# syntax=docker/dockerfile:1
ARG ZIG_VERSION=0.14.1

FROM debian:bookworm-slim AS build
ARG TARGETARCH
ARG ZIG_VERSION
WORKDIR /src/agent

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) zig_arch="x86_64" ;; \
      arm64) zig_arch="aarch64" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -s /opt/zig/zig /usr/local/bin/zig

COPY agent/build.zig agent/build.zig.zon ./
COPY agent/src ./src
RUN zig build -Doptimize=ReleaseSafe

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/agent/zig-out/bin/tawny-agent /usr/local/bin/tawny-agent
COPY docker/agent/entrypoint.sh /usr/local/bin/tawny-agent-entrypoint

RUN chmod +x /usr/local/bin/tawny-agent /usr/local/bin/tawny-agent-entrypoint \
    && mkdir -p /etc/tawny /var/lib/tawny

VOLUME ["/etc/tawny"]
ENTRYPOINT ["/usr/local/bin/tawny-agent-entrypoint"]
