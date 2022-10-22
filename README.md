# ambula

This project aims to implement a minimal blockchain running an alternative puzzle algorithm to Bitcoin Proof of Work (PoW) called Proof of Interaction (PoI).  
This new puzzle does not consume nearly as much energy as PoW as it is based on network communication delay instead of raw compute.  

# Build

`CGO_ENABLED=0 GOOS=linux go build -o ./ambula`

# Test

`go test ./...`