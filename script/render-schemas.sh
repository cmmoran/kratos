#!/bin/sh

set -eux pipefail

ory_x_library="cmmoran/ory-x"
ory_x_version="$(go list -f '{{.Replace.Version}}' -m github.com/ory/x | cut -d '-' -f3)"

sed 's!ory://tracing-config!https://raw.githubusercontent.com/'${ory_x_library}'/'${ory_x_version}'/otelx/config.schema.json!g;' embedx/config.schema.json > .schemastore/config.schema.json

git add embedx/config.schema.json
