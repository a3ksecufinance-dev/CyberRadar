FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY internal/ internal/
COPY services/iga/ services/iga/
COPY go.work go.work
COPY go.work.sum go.work.sum

WORKDIR /workspace/services/iga
RUN go build -o /iga-service ./cmd/server

FROM scratch
COPY --from=builder /iga-service /iga-service
EXPOSE 8024
ENTRYPOINT ["/iga-service"]
