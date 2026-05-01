ARG ZEEK_IMAGE=zeek/zeek:lts

FROM golang:1.26-bookworm AS build

ARG VERSION=unknown
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build \
  -ldflags "-X cute-pcap-mcp/internal/buildinfo.version=${VERSION} -X cute-pcap-mcp/internal/buildinfo.commit=${COMMIT} -X cute-pcap-mcp/internal/buildinfo.buildTime=${BUILD_TIME}" \
  -o /out/cute-pcap-mcp ./cmd/cute-pcap-mcp

FROM ${ZEEK_IMAGE}

ENV PATH="/usr/local/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

USER root

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    tshark \
    tcpdump \
    jq \
    python3 \
  && rm -rf /var/lib/apt/lists/*

# Smoke check that every binary the runtime promises is on PATH.
# Builds fail loudly here rather than at first MCP call.
RUN set -eu; \
    for bin in tshark capinfos tcpdump zeek jq python3; do \
      command -v "$bin" >/dev/null 2>&1 || { echo "$bin missing from runtime image" >&2; exit 1; }; \
    done

RUN if ! getent passwd pcapmcp >/dev/null; then \
    useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin pcapmcp; \
  fi
COPY --from=build /out/cute-pcap-mcp /usr/local/bin/cute-pcap-mcp
# /work is the canonical bind-mount target. The image creates an empty
# layout; the operator overlays it with `-v ~/mcp-work:/work`.
RUN mkdir -p /work/pcaps /work/output /work/tmp && chown -R 10001:10001 /work
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/cute-pcap-mcp"]
