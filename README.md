## tact

[![Unit tests](https://github.com/kordega/tact/actions/workflows/ci.yaml/badge.svg)](https://github.com/kordega/tact/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/kordega/tact)](LICENSE)
[![OpenTofu supported](https://img.shields.io/badge/OpenTofu-supported-844FBA?logo=opentofu&logoColor=white)](https://opentofu.org/)
![Terraform not supported](https://img.shields.io/badge/Terraform-not_supported-red?logo=terraform&logoColor=white)

> [!WARNING]
> No Terraform support. [[1]]

[1]: https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license

OpenTofu 1.10 is the oldest supported release. It is the first one that
implements OpenTelemetry tracing and the state lock file, and CI is matrixed
over 1.10 and up.

## Usage

### `skeleton-static-analysis.yaml`

Runs `tofu fmt` and the bundled rego policies over the whole repository.

```yaml
name: Static analysis

on:
  pull_request:
    branches: [ '**' ]

permissions:
  contents: read

jobs:
  static-analysis:
    uses: kordega/tact/.github/workflows/skeleton-static-analysis.yaml@main
    with:
      tofu-version: '1.11.5'
```

### `skeleton-plan-apply.yaml`

Plans on every run and applies when the plan has changes.

```yaml
name: Plan and apply

on:
  pull_request:
    branches: [ '**' ]
  push:
    branches: [ 'main' ]

permissions:
  contents: read

jobs:
  plan-apply:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets: inherit
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
```

`environment` names the GitHub Environment the apply job runs in, so required
reviewers configured there gate the apply.

Plan without applying, for pull requests:

```yaml
jobs:
  plan:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets: inherit
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
      tofu-apply: false
```

One job per root:

```yaml
jobs:
  plan-apply:
    strategy:
      fail-fast: false
      matrix:
        root:
          - prd-tfstate
          - prd-cloudflare-dns
          - prd-github-organization
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets: inherit
    with:
      tofu-version-file: .tofu-version
      chroot-directory: roots/${{ matrix.root }}
      environment: production
```

### Secrets

Everything tofu needs goes through `extra-secret-environment-variables`, a
newline-separated list of `NAME=VALUE` pairs. Each value is double
base64-encoded so it survives as a secret string, and every value is masked
before any tofu step runs.

```console
$ printf '%s' "my-secret" | base64 | base64
```

Store the encoded pairs as a single repository secret:

```text
TF_VAR_db_password=<base64(base64(password))>
TF_VAR_api_key=<base64(base64(key))>
```

```yaml
jobs:
  plan-apply:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets:
      extra-secret-environment-variables: ${{ secrets.TOFU_SECRET_ENV }}
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
```

### Telemetry

Two things can be traced, and they are enabled separately. `tofu-telemetry-*`
covers what OpenTofu does inside a job — the graph walk, the provider calls. And
`workflow-telemetry-*` covers the run around it — how long each job queued and
ran, and which of them failed. Both export over OTLP and can share a backend.

#### OpenTofu traces

OpenTofu exports traces over OTLP, so any OTLP receiver works as the collector
— Jaeger, Grafana Tempo or an OpenTelemetry Collector in front of them. Nothing
is exported unless `tofu-telemetry-enabled` is set to `true`.

```yaml
jobs:
  plan-apply:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets: inherit
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
      tofu-telemetry-enabled: true
      tofu-telemetry-endpoint: http://jaeger.internal:4318
      tofu-telemetry-insecure: true
```

Traces are reported under `tofu-<environment>`, so the run above shows up in
Jaeger as the service `tofu-production`. Override it with
`tofu-telemetry-service-name` when one environment spans several roots and each
needs its own service.

> [!IMPORTANT]
> The port has to match the protocol. OpenTofu defaults to `http/protobuf`,
> which Jaeger serves on `4318`. Pointing at the gRPC port `4317` without
> setting `tofu-telemetry-protocol: grpc` exports into a port that cannot decode
> the request, and tofu still exits `0` — the traces just never arrive.

```yaml
    with:
      tofu-telemetry-enabled: true
      tofu-telemetry-endpoint: http://jaeger.internal:4317
      tofu-telemetry-protocol: grpc
      tofu-telemetry-insecure: true
```

The skeleton hands these to the `tofu-setup` action, whose own inputs keep the
bare `telemetry-` prefix, and which maps them onto the standard OpenTelemetry
environment variables for every tofu command that follows in the job:

| Skeleton input                | `tofu-setup` input       | Environment variable          |
| ----------------------------- | ------------------------ | ----------------------------- |
| `tofu-telemetry-exporter`     | `telemetry-exporter`     | `OTEL_TRACES_EXPORTER`        |
| `tofu-telemetry-endpoint`     | `telemetry-endpoint`     | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `tofu-telemetry-protocol`     | `telemetry-protocol`     | `OTEL_EXPORTER_OTLP_PROTOCOL` |
| `tofu-telemetry-insecure`     | `telemetry-insecure`     | `OTEL_EXPORTER_OTLP_INSECURE` |
| `tofu-telemetry-service-name` | `telemetry-service-name` | `OTEL_SERVICE_NAME`           |

`tofu-telemetry-insecure: true` sends traces in plaintext, so keep it for collectors
reachable only over a private network. A collector behind authentication reads
its credentials from `OTEL_EXPORTER_OTLP_HEADERS`, which belongs in
`extra-secret-environment-variables` rather than in a workflow input.

#### Workflow traces and metrics

Both skeletons can report the run itself — a span per job and step, plus the
`github.workflow.duration`, `github.job.duration` and `github.job.queued_duration`
metrics — through
[paper2/github-actions-opentelemetry](https://github.com/paper2/github-actions-opentelemetry).
It runs as a final job that reads the finished run back from the GitHub API, so
it reports whether the run passed, failed or skipped the apply.

```yaml
permissions:
  contents: read
  # The telemetry job reads the run back from the API with whatever token the
  # caller hands down — it requests nothing of its own, so a private repository
  # has to grant this here. Public repositories can leave it out.
  actions: read

jobs:
  plan-apply:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets:
      workflow-telemetry-headers: ${{ secrets.OTLP_HEADERS }}
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
      workflow-telemetry-enabled: true
      workflow-telemetry-endpoint: https://otlp-gateway-prod-eu-west-6.grafana.net/otlp
      workflow-telemetry-service-name: github-actions
      workflow-telemetry-resource-attributes: environment=ci,team=platform
```

| Input                                    | Environment variable          |
| ---------------------------------------- | ----------------------------- |
| `workflow-telemetry-endpoint`            | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `workflow-telemetry-protocol`            | `OTEL_EXPORTER_OTLP_PROTOCOL` |
| `workflow-telemetry-service-name`        | `OTEL_SERVICE_NAME`           |
| `workflow-telemetry-resource-attributes` | `OTEL_RESOURCE_ATTRIBUTES`    |
| `workflow-telemetry-headers` (secret)    | `OTEL_EXPORTER_OTLP_HEADERS`  |

A hosted backend authenticates through the headers, which is why they are a
secret rather than an input. For a Grafana Cloud OTLP gateway the secret holds
one header, built from the instance ID and an access policy token:

```sh
printf '%s' "<instance-id>:<token>" | base64 -w0
```

```txt
Authorization=Basic <the base64 above>
```

`workflow-telemetry-protocol` defaults to `http/protobuf`, which is what the
hosted OTLP gateways serve. Set it to `grpc` only for a collector addressed on
its gRPC port.

> [!NOTE]
> Each skeleton reports its own run. A repository whose static analysis and
> plan/apply live in separate workflows gets a trace per workflow, not one
> trace spanning both.
