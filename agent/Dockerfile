# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS build
ARG TARGETARCH
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256_AMD64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_SHA256_ARM64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
WORKDIR /src

RUN apk add --no-cache curl xz
RUN case "$TARGETARCH" in \
      amd64) zig_arch="x86_64-linux"; zig_target="x86_64-linux-musl"; zig_sha256="$ZIG_SHA256_AMD64" ;; \
      arm64) zig_arch="aarch64-linux"; zig_target="aarch64-linux-musl"; zig_sha256="$ZIG_SHA256_ARM64" ;; \
      *) echo "Unsupported Docker target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && echo "${zig_sha256}  /tmp/zig.tar.xz" | sha256sum -c - \
    && tar -C /opt -xf /tmp/zig.tar.xz \
    && ln -s "/opt/zig-${zig_arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig \
    && echo "$zig_target" > /tmp/zig-target

COPY build.zig build.zig.zon ./
COPY src ./src
RUN zig build -Dtarget="$(cat /tmp/zig-target)" -Doptimize=ReleaseSmall

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS runtime
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 tawny \
    && adduser -S -D -H -u 65532 -G tawny tawny
COPY --from=build /src/zig-out/bin/tawny-agent /usr/local/bin/tawny-agent
COPY docker-entrypoint.sh /usr/local/bin/tawny-docker-entrypoint
RUN chmod 0755 /usr/local/bin/tawny-agent /usr/local/bin/tawny-docker-entrypoint \
    && mkdir -p /etc/tawny /var/lib/tawny \
    && chown -R tawny:tawny /etc/tawny /var/lib/tawny
ENV TAWNY_CONFIG=/etc/tawny/config.toml
ENV TAWNY_STATE_PATH=/var/lib/tawny/state.toml
VOLUME ["/etc/tawny", "/var/lib/tawny"]
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD test "$(cat /proc/1/comm)" = "tawny-agent" || exit 1
ENTRYPOINT ["tawny-docker-entrypoint"]
