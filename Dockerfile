# syntax=docker/dockerfile:1

FROM golang:1.23.2-bookworm

WORKDIR /src

ENV CGO_ENABLED=1 \
    HOME=/tmp \
    GOCACHE=/tmp/go-build \
    STATICCHECK_CACHE=/tmp/staticcheck

COPY go.mod go.sum ./
RUN go mod download
RUN go install honnef.co/go/tools/cmd/staticcheck@v0.6.1 \
    && go install golang.org/x/tools/cmd/deadcode@v0.36.0

COPY . .

RUN test ! -d tools \
    && test ! -d lattice-estimator-main \
    && test ! -f prf/generate_params.sage \
    && test ! -f prf/sweep_rounds.sage \
    && test ! -f prf/RUN_SAGE.md

RUN go test ./...
RUN go build -o /usr/local/bin/issuance ./cmd/issuance \
    && go build -o /usr/local/bin/showing ./cmd/showing \
    && chmod +x scripts/artifact-entrypoint.sh \
        scripts/artifact-test.sh \
        scripts/artifact-bench.sh \
        scripts/artifact-gate.sh \
        scripts/validate-artifact.sh \
        scripts/stress-ntru-keygen.sh \
    && mkdir -p /artifacts \
    && chmod 1777 /artifacts \
    && rm -rf "$GOCACHE" "$STATICCHECK_CACHE"

ENV GOPROXY=off

ENTRYPOINT ["./scripts/artifact-entrypoint.sh"]
CMD ["help"]
