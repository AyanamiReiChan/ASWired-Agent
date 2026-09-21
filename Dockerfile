FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/xray-core ./third_party/xray-core
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /aswired-agent ./cmd/aswired-agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=build /aswired-agent /usr/local/bin/aswired-agent
VOLUME ["/var/lib/aswired-agent"]
ENTRYPOINT ["/usr/local/bin/aswired-agent"]
CMD ["-config", "/etc/aswired-agent/agent.json"]
