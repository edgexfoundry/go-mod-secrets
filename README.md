# EdgeX Secrets Module

[![Build Status](https://jenkins.edgexfoundry.org/view/EdgeX%20Foundry%20Project/job/edgexfoundry/job/go-mod-secrets/job/main/badge/icon)](https://jenkins.edgexfoundry.org/view/EdgeX%20Foundry%20Project/job/edgexfoundry/job/go-mod-secrets/job/main/) [![Code Coverage](https://codecov.io/gh/edgexfoundry/go-mod-secrets/branch/main/graph/badge.svg?token=KrqJoby1fK)](https://codecov.io/gh/edgexfoundry/go-mod-secrets) [![Go Report Card](https://goreportcard.com/badge/github.com/edgexfoundry/go-mod-secrets)](https://goreportcard.com/report/github.com/edgexfoundry/go-mod-secrets) [![GitHub Latest Dev Tag)](https://img.shields.io/github/v/tag/edgexfoundry/go-mod-secrets?include_prereleases&sort=semver&label=latest-dev)](https://github.com/edgexfoundry/go-mod-secrets/tags) ![GitHub Latest Stable Tag)](https://img.shields.io/github/v/tag/edgexfoundry/go-mod-secrets?sort=semver&label=latest-stable) [![GitHub License](https://img.shields.io/github/license/edgexfoundry/go-mod-secrets)](https://choosealicense.com/licenses/apache-2.0/) ![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/edgexfoundry/go-mod-secrets) [![GitHub Pull Requests](https://img.shields.io/github/issues-pr-raw/edgexfoundry/go-mod-secrets)](https://github.com/edgexfoundry/go-mod-secrets/pulls) [![GitHub Contributors](https://img.shields.io/github/contributors/edgexfoundry/go-mod-secrets)](https://github.com/edgexfoundry/go-mod-secrets/contributors) [![GitHub Committers](https://img.shields.io/badge/team-committers-green)](https://github.com/orgs/edgexfoundry/teams/go-mod-secrets-committers/members) [![GitHub Commit Activity](https://img.shields.io/github/commit-activity/m/edgexfoundry/go-mod-secrets)](https://github.com/edgexfoundry/go-mod-secrets/commits)

## Delayed Start Go Build Tags

The delayed start feature is conditional built with go build tags `delayedstart`.
The default behavior is not included. If other go services or go module would like to build with this feature,
please build them with additional go build tags like the following:

```console
user$ go build <otherservice.go> -tags delayedstart 
```

## Community
- Chat: https://chat.edgexfoundry.org/home
- Mailing lists: https://lists.edgexfoundry.org/mailman/listinfo

## License
[Apache-2.0](LICENSE)
