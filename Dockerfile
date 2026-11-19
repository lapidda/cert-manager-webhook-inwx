# Build stage: full Go toolchain, never shipped.
FROM golang:1.27 AS build
WORKDIR /src
# Dependencies first, so this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off => fully static binary, so the runtime image needs no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /webhook .

# Runtime stage: distroless "static" has CA certificates, tzdata and a
# nonroot user (uid 65532), but no shell and no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /webhook /webhook
USER 65532:65532
ENTRYPOINT ["/webhook"]
