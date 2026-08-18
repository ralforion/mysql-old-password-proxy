# Multi-stage: build with the Go toolchain, ship the static binary on scratch.
#
# The final image contains exactly one file — the binary. No shell, no libc, no
# package manager, no /bin at all, so there is nothing to pivot into if the
# process is ever compromised, and nothing to patch on a CVE treadmill.
#
# This works because the proxy needs nothing from a filesystem:
#   - CGO is off, so there is no dynamic linker and no libc.
#   - It makes no TLS connections, so no CA bundle is needed.
#   - It logs in UTC, so no tzdata is needed.
#   - DNS uses Go's pure resolver, reading the /etc/resolv.conf that the
#     container runtime mounts in.
#
# If you would rather have a base with /etc/passwd and CA certificates — for a
# scanner that insists on them — swap the final stage for:
#   FROM gcr.io/distroless/static-debian12:nonroot
#
# The build stage below is a normal Go image with a shell and a package manager.
# None of it ships: only /out/mysql-old-password-proxy is copied into the final
# stage, so the alpine layers exist during `docker build` and are discarded.
# Its version is pinned exactly, and must be at least the version in go.mod —
# a floating tag that drifted lower would make the toolchain download the right
# one mid-build, which needs network access and is not reproducible.
#
# --platform=$BUILDPLATFORM pins this stage to the architecture of the machine
# doing the building, and Go then cross-compiles to $TARGETARCH. Without it,
# buildx runs the whole stage under the *target* architecture — meaning the Go
# compiler itself executes under QEMU emulation for every foreign platform,
# which turns a seconds-long build into a minutes-long one. Go cross-compiles
# natively with CGO off, so emulation buys nothing here.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build

WORKDIR /src

# go.mod alone first, so the toolchain layer survives source changes. There are
# no third-party dependencies to download.
COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/mysql-old-password-proxy .

# CGO_ENABLED=0 on a package tree that imports no cgo is what actually
# guarantees a static binary, and the release workflow proves it by running the
# published image — which has no dynamic linker to fall back on. An ldd check
# here would be theatre: cross-compiled output cannot be inspected by the build
# platform's ldd anyway, so it would pass without testing anything.

FROM scratch

COPY --from=build /out/mysql-old-password-proxy /mysql-old-password-proxy

# 65532 is the conventional "nonroot" uid; scratch has no /etc/passwd, so it is
# numeric, which is what Kubernetes runAsNonRoot wants anyway.
USER 65532:65532

# 3306 is the MySQL port clients connect to; 8081 serves /healthz.
EXPOSE 3306 8081

ENTRYPOINT ["/mysql-old-password-proxy"]
