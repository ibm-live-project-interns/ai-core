FROM golang:alpine AS builder

WORKDIR /app

# Copy files relative to Root Context
COPY ai-core/go.mod ai-core/go.sum ./
# Copy shared dependency for replace directive
COPY ingestor/shared /ingestor/shared

RUN go mod download

COPY ai-core/ .
RUN go build -o ai-core .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/ai-core .

CMD ["./ai-core"]
