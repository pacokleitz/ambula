default:
	@just --list

fmt:
	go fmt ./...
	
lint:
	golangci-lint run	

test:
	go test ./...
	
check: fmt lint test

build:
	CGO_ENABLED=0 GOOS=linux go build -o ./ambula

run:
	go run .
	
docker:
	docker build -t ambula .
	docker run -p 1984:1984 ambula
