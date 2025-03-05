
<a name="Secrets Go Mod Changelog"></a>
## Secrets Module (in Go)
[Github repository](https://github.com/edgexfoundry/go-mod-secrets)

## Change Logs for EdgeX Dependencies

- [go-mod-core-contracts](https://github.com/edgexfoundry/go-mod-core-contracts/blob/main/CHANGELOG.md)

## [v4.0.0] - 2025-03-12

### ✨Features

- Add `CreateOrUpdateTokenRole` method for SecretStoreClient ([376921a…](https://github.com/edgexfoundry/go-mod-secrets/commit/376921a5bff43fe35ce0fa21d54be415799ba008))
- Add new methods for SecretStoreClient ([#307](https://github.com/edgexfoundry/go-mod-secrets/issues/307)) ([f4e54c9…](https://github.com/edgexfoundry/go-mod-secrets/commit/f4e54c98d67687ab4295b4342465ed9c03a95afb))
```text

BREAKING CHANGE: Add new methods for SecretStoreClient

```
### ♻ Code Refactoring

- Update module to v4 and replace vault with openbao ([c604dee…](https://github.com/edgexfoundry/go-mod-secrets/commit/c604deef9d980f328dd19e8d82b75e5278f54000))
```text

BREAKING CHANGE: 
- Update go module to v4 
- Replace Vault with OpenBao
```

### 🐛 Bug Fixes

- Correct the status code when calling secret store HealthCheck API ([#237](https://github.com/edgexfoundry/go-mod-secrets/issues/237)) ([3e242a2…](https://github.com/edgexfoundry/go-mod-secrets/commit/3e242a2355c48e9c7f5a2551a8a73a66823128f4))

### 👷 Build

- Upgrade to go-1.23, Linter1.61.0 ([1fa2d65…](https://github.com/edgexfoundry/go-mod-secrets/commit/1fa2d65bcea9fc3d2774ec3c6b4fddc928690939))

## [v3.1.0] - 2023-11-15

### 🐛 Bug Fixes

- *(security)* Allow underscores in service keys / Vault usernames ([#219](https://github.com/edgexfoundry/go-mod-secrets/issues/219)) ([8fb6d1b…](https://github.com/edgexfoundry/go-mod-secrets/commit/8fb6d1b0386788cfd9b74cd06fe2c4d5ecf1c81f))

### 👷 Build

- Upgrade to go 1.21 and linter 1.54.2 ([#226](https://github.com/edgexfoundry/go-mod-secrets/issues/226)) ([48a709c…](https://github.com/edgexfoundry/go-mod-secrets/commit/48a709c2b7f052d5ea8334acb6c02c03a8f30738))

## [v3.0.0] - 2023-05-31

### Features ✨

- Add Ability to set JWT audience claim ([#f3306c0](https://github.com/edgexfoundry/go-mod-secrets/commit/f3306c0886e2eb0c9d9ff51f22dc8190f0523958))
  ```text
  BREAKING CHANGE: JWTs can now be created with a fix audience value. Needed for OpenZiti integration
  ```
- Enabling hooks for Vault identity features ([#171](https://github.com/edgexfoundry/go-mod-secrets/issues/171)) ([#53c30ee](https://github.com/edgexfoundry/go-mod-secrets/commits/53c30ee))

### Bug Fixes 🐛

- CheckIdentityKeyExists was comparing to constant ([#192](https://github.com/edgexfoundry/go-mod-secrets/issues/192)) ([#3201b0f](https://github.com/edgexfoundry/go-mod-secrets/commits/3201b0f))

### Code Refactoring ♻

- Refactor all usages of path to be SecretName in APIs and InsecureSecrets configuration ([#9c30f8a](https://github.com/edgexfoundry/go-mod-secrets/commit/9c30f8aa9282133db9d8ebe4ffa800148d72dd72))
  ```text
  BREAKING CHANGE: Path renamed SecretName, GetSecrets renamed to GetSecret, StoreSecrets renamed to StoreSecret, GetKeys renamed to GetSecretNames
  ```
- Update module to v3 ([#52131f2](https://github.com/edgexfoundry/go-mod-secrets/commit/52131f2bd3a06dc9d4c81360f9be7df2f5aefe44))
  ```text
  BREAKING CHANGE: Import paths will need to change to v3
  ```

### Build 👷

- Update to Go 1.20 and linter v1.51.2 ([#195](https://github.com/edgexfoundry/go-mod-secrets/issues/195)) ([#ece5487](https://github.com/edgexfoundry/go-mod-secrets/commits/ece5487))

## [v2.3.0] - 2022-11-09

### Features ✨

- Add Consul access and role interface ([#163](https://github.com/edgexfoundry/go-mod-secrets/issues/163)) ([#7e745c8](https://github.com/edgexfoundry/go-mod-secrets/commits/7e745c8))
- Add GetKey API ([#161](https://github.com/edgexfoundry/go-mod-secrets/issues/161)) ([#46e806f](https://github.com/edgexfoundry/go-mod-secrets/commits/46e806f))
- Add error handling for status 404 ([#160](https://github.com/edgexfoundry/go-mod-secrets/issues/160)) ([#c185b68](https://github.com/edgexfoundry/go-mod-secrets/commits/c185b68))

### Build 👷

- Upgrade to Go 1.18 ([#995c520](https://github.com/edgexfoundry/go-mod-secrets/commits/995c520))

## [v2.2.0] - 2022-05-11

### Features ✨

- **security:** implement runtime token provider GetRawToken client API call for obtaining secret store token ([#141](https://github.com/edgexfoundry/go-mod-secrets/issues/141)) ([#7ea7921](https://github.com/edgexfoundry/go-mod-secrets/commits/7ea7921))

### Bug Fixes 🐛

- close response Body when the returned error is nil ([#146](https://github.com/edgexfoundry/go-mod-secrets/issues/146)) ([#3ba02e4](https://github.com/edgexfoundry/go-mod-secrets/commits/3ba02e4))

### Build 👷

- **security:** Add go build tags for non-delayed start builds ([#144](https://github.com/edgexfoundry/go-mod-secrets/issues/144)) ([#8f104b7](https://github.com/edgexfoundry/go-mod-secrets/commits/8f104b7))
- **security:** Enable gosec and default linter set ([#05e2b9d](https://github.com/edgexfoundry/go-mod-secrets/commits/05e2b9d))
- 
## [2.1.0] - 2021-11-17

### Features ✨

- Add ability to set Auth Token for SecretClient ([#655d426](https://github.com/edgexfoundry/go-mod-secrets/commits/655d426))

- Add SecretsFile config setting ([#0a5a284](https://github.com/edgexfoundry/go-mod-secrets/commits/0a5a284))

## [2.0.0] - 2021-06-30
### Features ✨
- **security:** Add GenerateConsulToken API to SecretClient interface ([#6432e0d](https://github.com/edgexfoundry/go-mod-secrets/commits/6432e0d))
- **security:** Add Generate Registry Token API for secretstore client ([#5e2f4d4](https://github.com/edgexfoundry/go-mod-secrets/commits/5e2f4d4))
### Bug Fixes 🐛
- Reduce the resource constraints as too many semaphores costs now ([#1b8a009](https://github.com/edgexfoundry/go-mod-secrets/commits/1b8a009))
- **security:** Fix JSON structure of token self response ([#d9d1b45](https://github.com/edgexfoundry/go-mod-secrets/commits/d9d1b45))
### Code Refactoring ♻
- Tweaked GenerateConsulToken to use service's own token ([#fe93ff0](https://github.com/edgexfoundry/go-mod-secrets/commits/fe93ff0))
- Change unseal to just take KeysBase64 ([#f998050](https://github.com/edgexfoundry/go-mod-secrets/commits/f998050))
- Refactor to be proper abstraction of a SecretStore ([#89b3b67](https://github.com/edgexfoundry/go-mod-secrets/commits/89b3b67))
    ```
    BREAKING CHANGE:
    All existing SecretStore configuration must add `Type = 'vault'`
    ```
    <a name="v0.0.30"></a>
## [v0.0.30] - 2021-01-07
### Code Refactoring ♻
- Resolve compiler errors in unit test when using latest go-mod-core-contracts ([#7271790](https://github.com/edgexfoundry/go-mod-secrets/commits/7271790))

<a name="v0.0.28"></a>
## [v0.0.28] - 2020-12-15
### Code Refactoring ♻
- Implement better abstraction for use in Secret Provider ([#62837fd](https://github.com/edgexfoundry/go-mod-secrets/commits/62837fd))

<a name="v0.0.21"></a>
## [v0.0.21] - 2020-09-16
### Bug Fixes 🐛
- Remove trailing slash from vault URL to avoid 400 error ([#1487bb7](https://github.com/edgexfoundry/go-mod-secrets/commits/1487bb7))
