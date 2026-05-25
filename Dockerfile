# webhook-rfc2136/Dockerfile
#
# CGO must be enabled: bodgit/tsig/gss links against the system Kerberos
# C library (MIT krb5 / GSSAPI). A pure-Go build (CGO_ENABLED=0) would link
# but fail at runtime when initialising the GSS context.
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache build-base krb5-dev pkgconfig
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/webhook ./cmd/webhook

FROM alpine:3.20
RUN apk add --no-cache krb5 krb5-libs ca-certificates && rm -rf /var/cache/apk/*
COPY --from=builder /out/webhook /usr/local/bin/webhook
USER 65534:65534
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:9090/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/webhook"]
