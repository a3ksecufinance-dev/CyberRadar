FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY internal/ internal/
COPY services/netsec/ services/netsec/
COPY go.work go.work
COPY go.work.sum go.work.sum

WORKDIR /workspace/services/netsec
RUN go build -o /netsec-service ./cmd/server

FROM scratch
COPY --from=builder /netsec-service /netsec-service
EXPOSE 8022
ENTRYPOINT ["/netsec-service"]
