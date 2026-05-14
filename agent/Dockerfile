# syntax=docker/dockerfile:1
FROM alpine:3.20 AS build
ARG TARGETARCH
ARG ZIG_VERSION=0.14.0
WORKDIR /src

RUN apk add --no-cache curl xz
RUN case "$TARGETARCH" in \
      amd64) zig_arch="x86_64"; zig_target="x86_64-linux-musl" ;; \
      arm64) zig_arch="aarch64"; zig_target="aarch64-linux-musl" ;; \
      *) echo "Unsupported Docker target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && tar -C /opt -xf /tmp/zig.tar.xz \
    && ln -s "/opt/zig-linux-${zig_arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig \
    && echo "$zig_target" > /tmp/zig-target

COPY build.zig build.zig.zon ./
COPY src ./src
RUN zig build -Dtarget="$(cat /tmp/zig-target)" -Doptimize=ReleaseSmall

FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates curl jq openssl
COPY --from=build /src/zig-out/bin/tawny-agent /usr/local/bin/tawny-agent
COPY docker-entrypoint.sh /usr/local/bin/tawny-docker-entrypoint
RUN chmod 0755 /usr/local/bin/tawny-agent /usr/local/bin/tawny-docker-entrypoint \
    && mkdir -p /etc/tawny /var/lib/tawny
ENV TAWNY_CONFIG=/etc/tawny/config.toml
VOLUME ["/etc/tawny", "/var/lib/tawny"]
ENTRYPOINT ["tawny-docker-entrypoint"]
