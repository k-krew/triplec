.PHONY: build test lint clean

BINARY_NAME=triplec
MAIN_PATH=./cmd/triplec

build:
	go build -o $(BINARY_NAME) $(MAIN_PATH)

test:
	go test -v -race ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
