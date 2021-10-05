#
# Copyright (c) 2019 Dell Technologies, Inc
#
# SPDX-License-Identifier: Apache-2.0
#

.PHONY: test

GO=CGO_ENABLED=1 GO111MODULE=on go

tidy:
	go mod tidy

test:
	$(GO) test -count=1 -race ./... -coverprofile=coverage.out
	$(GO) vet ./...
	gofmt -l .
	[ "`gofmt -l .`" = "" ]