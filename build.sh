#!/bin/sh

#GOOS=linux go build -o ../monitor .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../monitor .