# webhook-rfc2136/Dockerfile
#
# bodgit/tsig/gss selects its GSSAPI implementation by build tag, not by CGO:
# the pure-Go gokrb5 one is the default, and the C one (openshift/gssapi,
# MIT krb5) only compiles under `-tags apcera`, which we never set. So CGO
# buys nothing here and the build stays static.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webhook ./cmd/webhook

# krb5 is here for the kinit binary, not for linking: internal/kerberos shells
# out to it to obtain the TGT.
FROM alpine:3.24
RUN apk add --no-cache krb5 krb5-libs ca-certificates && rm -rf /var/cache/apk/*
COPY --from=builder /out/webhook /usr/local/bin/webhook
USER 65534:65534
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:9090/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/webhook"]
