# Bicep templates. infra/azure is the source of truth for the deployed
# topology; deployment steps live in infra/azure/README.md and are not wrapped
# here.

set working-directory := ".."

[private]
default:
    @just --list --unsorted --justfile {{ source_file() }}

# Compile the templates and parameter files without deploying, as the CI bicep job does (needs az)
build:
    az bicep build --file infra/azure/main.bicep --stdout > /dev/null
    az bicep build-params --file infra/azure/main.bicepparam --stdout > /dev/null
    az bicep build-params --file infra/azure/main.bootstrap.bicepparam --stdout > /dev/null
    az bicep build --file infra/entra/main.bicep --stdout > /dev/null
    az bicep build-params --file infra/entra/main.bicepparam --stdout > /dev/null
