# syntax=docker/dockerfile:1

FROM golang:1.23.2-bookworm

WORKDIR /src

ENV CGO_ENABLED=1

COPY go.mod go.sum ./
RUN go mod download

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
        scripts/artifact-gate.sh

ENV GOPROXY=off

ENTRYPOINT ["./scripts/artifact-entrypoint.sh"]
CMD ["help"]
