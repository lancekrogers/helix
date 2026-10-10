# Bicep templates. infra/azure is the source of truth for the deployed
# topology; deployment steps live in infra/azure/README.md, except net-verify,
# the operator recipe below. net-sim is local tooling for the NSG rule table.

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

# Print the hosts approved apps and connection providers need and mark those missing from a deployed allow-list; arguments go to the script, e.g. --deployed a.example.com,b.example.com
[positional-arguments]
egress-hosts *args:
    pnpm --filter @azx-pbc/portal egress:hosts -- "$@"

# Simulate the egress NSG rule table with Docker networks and iptables, run the probe against stand-ins (needs a Docker daemon on this host, not the dev container); --static runs only the translator tests
[positional-arguments]
net-sim *args:
    node infra/netsim/run.mjs "$@"

# OPERATOR STEP, not CI: start the network probe job in a deployed install and print its result. Unverified in Azure by the work that added it; needs `az login` and the containerapp extension.
net-verify resource-group prefix='helix-prod':
    #!/usr/bin/env bash
    set -euo pipefail
    job_name="{{prefix}}-netprobe"
    rg="{{resource-group}}"
    exec_name="$(az containerapp job start -g "$rg" -n "$job_name" --query name -o tsv)"
    echo "started execution ${exec_name}"
    deadline=$(( $(date +%s) + 600 ))
    status="Unknown"
    while [ "$(date +%s)" -lt "$deadline" ]; do
      status="$(az containerapp job execution show -g "$rg" -n "$job_name" --job-execution-name "$exec_name" --query properties.status -o tsv 2>/dev/null || echo Running)"
      case "$status" in
        Running|Processing|Unknown|"") ;;
        *) break ;;
      esac
      sleep 10
    done
    echo "execution status: ${status}"
    logs=""
    log_deadline=$(( $(date +%s) + 180 ))
    while [ "$(date +%s)" -lt "$log_deadline" ]; do
      logs="$(az containerapp job logs show -g "$rg" -n "$job_name" --execution "$exec_name" --container netprobe --format text 2>/dev/null || true)"
      if [ -n "$logs" ]; then
        break
      fi
      sleep 15
    done
    if [ -z "$logs" ]; then
      echo "no probe output yet (Log Analytics may still be ingesting); retry: az containerapp job logs show -g $rg -n $job_name --execution $exec_name --container netprobe --format text"
    else
      printf '%s\n' "$logs"
    fi
    echo ""
    echo "The probe exercises outbound paths from snet-egress only. Before treating the install as healthy, run the edge→egress /health check from infra/azure/README.md (Verifying the isolation):"
    echo '  script -q /dev/null az containerapp exec -g <rg> -n <prefix>-edge --command \'
    echo '    "node -e \"fetch(process.env.EDGE_EGRESS_URL+'\''/health'\'').then(r=>console.log(r.status)).catch(e=>console.log('\''ERR'\'',e.cause?.code))\"" < /dev/null'
    echo "  expect: 200"
    if [ "$status" = "Succeeded" ]; then
      exit 0
    fi
    exit 1
