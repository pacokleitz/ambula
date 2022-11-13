## Node two stage image building

# Build
FROM golang:1.19 AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o ./ambula

# Deploy
FROM alpine:3 AS production

WORKDIR /app

COPY --from=build /app/ambula ./ambula

EXPOSE 1984

RUN adduser --disabled-password satoshi
USER satoshi

ENTRYPOINT ["./ambula"]
