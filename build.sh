#!/bin/bash

# With MacOS in mind 
export GOPATH=/Users/$USER/go
GOOS=js GOARCH=wasm go build -o main.wasm


# Now spin up a web page
python3 -m http.server 1337
