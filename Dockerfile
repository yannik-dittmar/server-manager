# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies for libpcap
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /app

# Copy go mod file and source code
COPY go.mod ./
COPY *.go ./

# Download dependencies and generate go.sum
RUN go mod tidy

# Build the binary with static linking where possible
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o server-control .

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache libpcap ca-certificates

# Create non-root user (but we'll need root for packet capture)
# We keep root for now since pcap requires it

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/server-control .

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep server-control || exit 1

ENTRYPOINT ["./server-control"]
