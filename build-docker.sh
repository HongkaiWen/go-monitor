#!/bin/sh

# https://stackoverflow.com/questions/12168873/cross-compile-go-on-osx

docker run --rm -it -v /Users/hongkai/go/src/monitor:/go/src/monitor -w /go/src/monitor golang:1.4.2-cross sh -c '
for GOOS in darwin linux windows; do
  for GOARCH in 386 amd64; do
    echo "Building $GOOS-$GOARCH"
    export GOOS=$GOOS
    export GOARCH=$GOARCH
    go build -o bin/ironcli-$GOOS-$GOARCH
  done
done
'