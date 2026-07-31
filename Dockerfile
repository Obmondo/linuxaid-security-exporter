FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/obmondo-security-exporter ./cmd/

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/obmondo-security-exporter /usr/local/bin/
ENTRYPOINT ["obmondo-security-exporter"]
CMD ["-config", "/etc/obmondo/security-exporter/config.yaml"]
