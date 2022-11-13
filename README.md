# ambula

This project aims to implement a minimal blockchain running an alternative puzzle algorithm to Bitcoin Proof of Work (PoW) called Proof of Interaction (PoI).  
This new puzzle does not consume nearly as much energy as PoW as it is based on network communication delay instead of raw compute.  

## Build binary

```CGO_ENABLED=0 GOOS=linux go build -o ./ambula```

## Build docker image

```docker build -t ambula .```

## Test

`go test ./...`

## Contribute

Look at our [coding conventions](https://github.com/pacokleitz/ambula/wiki/Coding-conventions) and how to [install our git pre-hooks](https://github.com/pacokleitz/ambula/wiki/Pre-hooks) to ensure you conform.  
