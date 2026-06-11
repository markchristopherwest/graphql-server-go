FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS build

# Provided automatically by buildx for each --platform target.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module-download layer: only re-runs when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# THE KEY LINE: CGO_ENABLED=0 produces a fully static binary with no libc
# dependency at all. The official Vault image is Alpine (musl libc); a binary
# dynamically linked against glibc would fail to exec there with a misleading
# "no such file or directory" (the file is present, its dynamic loader is not).
# A static binary sidesteps the whole musl-vs-glibc problem and runs on Alpine,
# distroless, or scratch — on any architecture.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o graphql-server .

RUN chmod +x graphql-server

# ^ point this at ./cmd/graphql-server if main lives there

# Final minimal stage (e.g., distroless or scratch)
FROM scratch
COPY --from=build /src/graphql-server /graphql-server

ENTRYPOINT [ "sh", "-c", "/graphql-server"] 
