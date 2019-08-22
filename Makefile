#
# Copyright (c) 2019 Dell Technologies, Inc
#
# SPDX-License-Identifier: Apache-2.0
#

.PHONY: test

GO=CGO_ENABLED=0 GO111MODULE=on go

test:
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) vet ./...
	gofmt -l .
	[ "`gofmt -l .`" = "" ]