FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/knowledgegraph/ services/knowledgegraph/

WORKDIR /workspace/services/knowledgegraph
RUN go build -trimpath -ldflags="-s -w" -o /knowledgegraph-service ./cmd/server

FROM scratch
COPY --from=builder /knowledgegraph-service /knowledgegraph-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8013
ENTRYPOINT ["/knowledgegraph-service"]
