FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/simpsync ./cmd/server

FROM alpine:3.20
RUN adduser -D -H -u 10001 app
WORKDIR /app
USER app
COPY --from=build /out/simpsync /app/simpsync
COPY --from=build /src/migrations /app/migrations
EXPOSE 8787
ENTRYPOINT ["/app/simpsync"]
