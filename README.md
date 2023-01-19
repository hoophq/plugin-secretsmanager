# Plugin Secrets Manager

This plugin integrates with most secrets manager out there.

## AWS Secrets Manager

**Required Configuration**

- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_REGION

## Publishing

```sh
# builds for linux/amd64 by default
PLUGIN_VERSION=vX.X.X make build && make publish
```

For testing purposes, like running the plugin locally for development:

```sh
GOOS=darwin GOARCH=arm64 PLUGIN_VERSION=vX.X.X make publish
```
