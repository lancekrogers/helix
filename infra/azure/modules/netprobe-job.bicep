// netprobe-job.bicep — scheduled and on-demand network posture probe (egress environment).
//
// WHY A JOB
// The probe dials forbidden and required destinations from snet-egress to learn
// whether the NSG, firewall, and application block list match what the template
// declares. That only proves something when the replica shares egress's subnet,
// NSG, and route table — not when it runs in appsEnv.
//
// WHY NO ROLE ASSIGNMENTS
// The probe uses only node:net and node:dns; it holds no vault secrets and calls
// no Azure API. A dedicated user-assigned identity with zero grants keeps a
// compromise worthless, unlike migrate-job.bicep which must read kv-platform.
//
// NOT A DEPLOY GATE: the schedule and alerts surface drift; an operator confirms
// with `just infra net-verify`. A failed run is a result to
// read, not something to retry into a pass — replicaRetryLimit is 0.
//
// Unverified in Azure: that the job starts on schedule and on demand, that the
// image tag carries the `probe` script, and that stdout lands in the egress
// environment's Log Analytics workspace for the alert queries.

@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Egress ACA environment resource id. The probe must run on snet-egress to exercise the same NSG and route table as egress.')
param acaEnvId string

@description('Egress image (the probe is a script inside it), e.g. ghcr.io/azx-pbc-oss/helix-egress:sha-xxxx. The tag must contain the probe script.')
param image string

@description('Cron for the scheduled run. Default daily 04:00 UTC. The job can also be started on demand.')
param cronExpression string = '0 4 * * *'

@description('Seconds before a stuck run is killed. 15 checks times a 5 s timeout is about 75 s; this leaves room for slow DNS.')
param replicaTimeout int = 300

@description('PROBE_* environment, built in main.bicep from the template\'s own values. Non-secret by construction.')
param probeEnv array

resource probeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-netprobe-id'
  location: location
}

resource job 'Microsoft.App/jobs@2024-03-01' = {
  name: '${namePrefix}-netprobe'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${probeIdentity.id}': {}
    }
  }
  properties: {
    environmentId: acaEnvId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: replicaTimeout
      replicaRetryLimit: 0
      scheduleTriggerConfig: {
        cronExpression: cronExpression
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'netprobe'
          image: image
          command: ['pnpm']
          args: ['--filter', '@azx-pbc/egress', 'probe']
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: probeEnv
        }
      ]
    }
  }
}

output jobName string = job.name
output jobId string = job.id
output identityPrincipalId string = probeIdentity.properties.principalId
