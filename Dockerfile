# ── build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependency downloads separately from the source build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/fetcher ./cmd/fetcher

# ── runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates: TLS roots for outbound HTTPS.
# tzdata: timezone support.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/fetcher /fetcher

ENTRYPOINT ["/fetcher"]
