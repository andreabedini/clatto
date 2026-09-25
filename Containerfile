# Build a static clatto binary and package it in a distroless image.
#
#   podman build -t ghcr.io/andreabedini/clatto:dev .
#
FROM docker.io/library/golang:1.26 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /clatto ./cmd/clatto

FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /clatto /clatto
COPY --from=build /src/examples/config.yaml /etc/clatto/config.yaml.example
EXPOSE 6464
ENTRYPOINT ["/clatto"]
