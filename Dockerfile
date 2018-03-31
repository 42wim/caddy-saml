FROM alpine:edge
ENTRYPOINT ["/bin/caddy"]
RUN apk update && apk add go git gcc musl-dev ca-certificates tzdata  \
            && mkdir -p /go/src/github.com/mholt \
            && mkdir /go/src/github.com/42wim \
            && git clone --branch saml --depth 1 https://github.com/42wim/caddy /go/src/github.com/mholt/caddy \
            && git clone --depth 1 https://github.com/42wim/caddy-saml /go/src/github.com/42wim/caddy-saml \
            && export GOPATH=/go \
            && cd /go/src/github.com/mholt/caddy/caddy \
            && go build \
            && cp caddy /bin/caddy \
            && rm -rf /go \
            && apk del --purge go gcc musl-dev
