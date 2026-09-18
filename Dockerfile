FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=${VERSION}" -o /bin/obmondo-security-exporter ./cmd/

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/obmondo-security-exporter /usr/local/bin/
# Reading a mounted host's package database needs no privileges: both the
# database and os-release are world-readable.
USER 65534:65534
ENTRYPOINT ["obmondo-security-exporter"]
CMD ["serve"]
