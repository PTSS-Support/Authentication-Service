# Build stage
FROM golang:1.22.3 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
RUN chmod +x /app/main
EXPOSE 8080
CMD ["./main"]