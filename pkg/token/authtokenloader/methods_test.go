//
// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2024-2025 IOTech Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//
// SPDX-License-Identifier: Apache-2.0'
//

package authtokenloader

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/token/fileioperformer/mocks"

	"github.com/stretchr/testify/assert"
)

const createTokenJSON = `{"auth":{"client_token":"some-token-value"}}` // nolint: gosec
const secretStoreInitJSON = `{"root_token":"some-token-value"}`        // nolint: gosec
const expectedToken = "some-token-value"
const entityIDJSON = `{"auth":{"entity_id": "mockEntityId"}}` // nolint: gosec
const expectedEntityID = "mockEntityId"

func TestReadCreateTokenJSON(t *testing.T) {
	stringReader := strings.NewReader(createTokenJSON)
	mockFileIoPerformer := &mocks.FileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, nil)

	p := NewAuthTokenLoader(mockFileIoPerformer)

	token, err := p.Load("/dev/null")
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestReadSecretStoreInitJSON(t *testing.T) {
	stringReader := strings.NewReader(secretStoreInitJSON)
	mockFileIoPerformer := &mocks.FileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, nil)

	p := NewAuthTokenLoader(mockFileIoPerformer)

	token, err := p.Load("/dev/null")
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestReadEmptyJSON(t *testing.T) {
	stringReader := strings.NewReader("{}")
	mockFileIoPerformer := &mocks.FileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, nil)

	p := NewAuthTokenLoader(mockFileIoPerformer)

	_, err := p.Load("/dev/null")
	assert.EqualError(t, err, "Unable to find authentication token in /dev/null")
}

func TestFailOpen(t *testing.T) {
	stringReader := strings.NewReader("")
	myerr := errors.New("error")
	mockFileIoPerformer := &mocks.FileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, myerr)

	p := NewAuthTokenLoader(mockFileIoPerformer)

	_, err := p.Load("/dev/null")
	assert.Equal(t, myerr, err)
}

func TestReadEntityIdJSON(t *testing.T) {
	stringReader := strings.NewReader(entityIDJSON)
	mockFileIoPerformer := &mocks.FileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, nil)

	p := NewAuthTokenLoader(mockFileIoPerformer)

	entityId, err := p.ReadEntityId("/dev/null")
	assert.Nil(t, err)
	assert.Equal(t, expectedEntityID, entityId)
}
