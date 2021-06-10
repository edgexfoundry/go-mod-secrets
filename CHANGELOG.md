
<a name="Secrets Go Mod Changelog"></a>
## Secrets Module (in Go)
[Github repository](https://github.com/edgexfoundry/go-mod-secrets)

## [2.0.0] - 2021-06-10
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
