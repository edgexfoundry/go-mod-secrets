#
# Copyright (c) 2018 Dell Technologies, Inc
#
# SPDX-License-Identifier: Apache-2.0
#

.PHONY: test

GO=CGO_ENABLED=0 GO111MODULE=on go

test:
	$(GO) test ./... -cover
	$(GO) vet ./...