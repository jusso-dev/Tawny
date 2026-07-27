# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256_AMD64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_SHA256_ARM64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build
ARG TARGETARCH
ARG ZIG_VERSION
ARG ZIG_SHA256_AMD64
ARG ZIG_SHA256_ARM64
WORKDIR /src/agent

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) zig_arch="x86_64"; zig_sha256="$ZIG_SHA256_AMD64" ;; \
      arm64) zig_arch="aarch64"; zig_sha256="$ZIG_SHA256_ARM64" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/zig.tar.xz --proto '=https' --tlsv1.2 --retry 3 \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"; \
    echo "${zig_sha256}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -s /opt/zig/zig /usr/local/bin/zig

COPY agent/build.zig agent/build.zig.zon ./
COPY agent/src ./src
RUN zig build -Doptimize=ReleaseSafe

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 tawny \
    && useradd --system --uid 65532 --gid tawny --no-create-home --shell /usr/sbin/nologin tawny

COPY --from=build /src/agent/zig-out/bin/tawny-agent /usr/local/bin/tawny-agent
COPY docker/agent/entrypoint.sh /usr/local/bin/tawny-agent-entrypoint

RUN chmod +x /usr/local/bin/tawny-agent /usr/local/bin/tawny-agent-entrypoint \
    && mkdir -p /etc/tawny /var/lib/tawny \
    && chown -R tawny:tawny /etc/tawny /var/lib/tawny

VOLUME ["/etc/tawny", "/var/lib/tawny"]
ENV TAWNY_STATE_PATH=/var/lib/tawny/state.toml
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD test "$(cat /proc/1/comm)" = "tawny-agent" || exit 1
ENTRYPOINT ["/usr/local/bin/tawny-agent-entrypoint"]
