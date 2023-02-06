// Code generated by mockery v2.15.0. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// SecretClient is an autogenerated mock type for the SecretClient type
type SecretClient struct {
	mock.Mock
}

// GenerateConsulToken provides a mock function with given fields: serviceKey
func (_m *SecretClient) GenerateConsulToken(serviceKey string) (string, error) {
	ret := _m.Called(serviceKey)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(serviceKey)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(serviceKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetKeys provides a mock function with given fields: subPath
func (_m *SecretClient) GetKeys(subPath string) ([]string, error) {
	ret := _m.Called(subPath)

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(subPath)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(subPath)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSecrets provides a mock function with given fields: subPath, keys
func (_m *SecretClient) GetSecrets(subPath string, keys ...string) (map[string]string, error) {
	_va := make([]interface{}, len(keys))
	for _i := range keys {
		_va[_i] = keys[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, subPath)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func(string, ...string) map[string]string); ok {
		r0 = rf(subPath, keys...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, ...string) error); ok {
		r1 = rf(subPath, keys...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetSelfJWT provides a mock function with given fields: serviceKey
func (_m *SecretClient) GetSelfJWT(serviceKey string) (string, error) {
	ret := _m.Called(serviceKey)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(serviceKey)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(serviceKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsJWTValid provides a mock function with given fields: jwt
func (_m *SecretClient) IsJWTValid(jwt string) (bool, error) {
	ret := _m.Called(jwt)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(jwt)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(jwt)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetAuthToken provides a mock function with given fields: ctx, token
func (_m *SecretClient) SetAuthToken(ctx context.Context, token string) error {
	ret := _m.Called(ctx, token)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreSecrets provides a mock function with given fields: subPath, _a1
func (_m *SecretClient) StoreSecrets(subPath string, _a1 map[string]string) error {
	ret := _m.Called(subPath, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, map[string]string) error); ok {
		r0 = rf(subPath, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewSecretClient interface {
	mock.TestingT
	Cleanup(func())
}

// NewSecretClient creates a new instance of SecretClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewSecretClient(t mockConstructorTestingTNewSecretClient) *SecretClient {
	mock := &SecretClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
