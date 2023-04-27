# Plugin Secrets Manager

This plugin integrates with external secrets manager

[Secret Manager Plugin Doc](https://hoop.dev/docs/plugins/secrets-manager)

## Publishing

```sh
# builds for linux/amd64 by default
PLUGIN_VERSION=vX.X.X make build
PLUGIN_VERSION=vX.X.X make publish
```

For testing purposes, like running the plugin locally for development:

```sh
GOOS=darwin GOARCH=arm64 PLUGIN_VERSION=vX.X.X make publish
```

## Development

```sh
PLUGIN_NAME=secretsmanager
CONN=bash

# expect env: ENV_CONFIG='{"HOST": ""}'
hoop admin create conn $CONN --overwrite \
    -e HOST envjson:ENV_CONFIG:HOST
    -a test-agent -- bash

hoop admin create plugin $PLUGIN_NAME --overwrite \
    --source=path:/tmp/ \
    --connection "$CONN"

go build -o /tmp/$PLUGIN_NAME main.go

hoop exec $CONN -i 'env'
```
