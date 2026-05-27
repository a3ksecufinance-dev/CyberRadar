FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/pipeline/ services/pipeline/

WORKDIR /workspace/services/pipeline
RUN go build -trimpath -ldflags="-s -w" -o /pipeline-worker ./cmd/worker

FROM scratch
COPY --from=builder /pipeline-worker /pipeline-worker
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/pipeline-worker"]
