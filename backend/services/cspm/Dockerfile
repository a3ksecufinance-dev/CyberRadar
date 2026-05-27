FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY internal/ internal/
COPY services/cspm/ services/cspm/
COPY go.work go.work
COPY go.work.sum go.work.sum

WORKDIR /workspace/services/cspm
RUN go build -o /cspm-service ./cmd/server

FROM scratch
COPY --from=builder /cspm-service /cspm-service
EXPOSE 8025
ENTRYPOINT ["/cspm-service"]
