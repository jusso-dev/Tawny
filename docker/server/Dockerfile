# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# Zig does not terminate TLS. Caddy does. This image is the HTTP server only.
ARG ZIG_VERSION=0.17.0
ARG ZIG_SHA256_AMD64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
ARG ZIG_SHA256_ARM64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build
ARG TARGETARCH
ARG ZIG_VERSION
ARG ZIG_SHA256_AMD64
ARG ZIG_SHA256_ARM64
WORKDIR /src

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

COPY server/build.zig server/build.zig.zon ./
COPY server/src ./src
RUN case "${TARGETARCH}" in \
      amd64) target=x86_64-linux-musl ;; \
      arm64) target=aarch64-linux-musl ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    zig build -Doptimize=ReleaseSafe -Dtarget="$target"

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/zig-out/bin/tawny-server /tawny-server
COPY server/ui /srv/tawny/ui
ENV TAWNY_UI_DIR=/srv/tawny/ui
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/tawny-server"]
CMD ["serve"]
