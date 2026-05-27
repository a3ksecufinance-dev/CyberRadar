FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY internal/ internal/
COPY services/risk/ services/risk/
COPY go.work go.work
COPY go.work.sum go.work.sum

WORKDIR /workspace/services/risk
RUN go build -o /risk-service ./cmd/server

FROM scratch
COPY --from=builder /risk-service /risk-service
EXPOSE 8023
ENTRYPOINT ["/risk-service"]
