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

OpenTofu exports traces over OTLP, so any OTLP receiver works as the collector
— Jaeger, Grafana Tempo or an OpenTelemetry Collector in front of them. Nothing
is exported unless `telemetry-enabled` is set to `true`.

```yaml
jobs:
  plan-apply:
    uses: kordega/tact/.github/workflows/skeleton-plan-apply.yaml@main
    secrets: inherit
    with:
      tofu-version: '1.11.5'
      chroot-directory: roots/prd-cloudflare-dns
      environment: production
      telemetry-enabled: true
      telemetry-endpoint: http://jaeger.internal:4318
      telemetry-insecure: true
```

Traces are reported under `tofu-<environment>`, so the run above shows up in
Jaeger as the service `tofu-production`. Override it with
`telemetry-service-name` when one environment spans several roots and each
needs its own service.

> [!IMPORTANT]
> The port has to match the protocol. OpenTofu defaults to `http/protobuf`,
> which Jaeger serves on `4318`. Pointing at the gRPC port `4317` without
> setting `telemetry-protocol: grpc` exports into a port that cannot decode
> the request, and tofu still exits `0` — the traces just never arrive.

```yaml
    with:
      telemetry-enabled: true
      telemetry-endpoint: http://jaeger.internal:4317
      telemetry-protocol: grpc
      telemetry-insecure: true
```

The inputs map onto the standard OpenTelemetry environment variables, which
`tofu-setup` exports for every tofu command that follows in the job:

| Input                    | Environment variable           |
| ------------------------ | ------------------------------ |
| `telemetry-exporter`     | `OTEL_TRACES_EXPORTER`         |
| `telemetry-endpoint`     | `OTEL_EXPORTER_OTLP_ENDPOINT`  |
| `telemetry-protocol`     | `OTEL_EXPORTER_OTLP_PROTOCOL`  |
| `telemetry-insecure`     | `OTEL_EXPORTER_OTLP_INSECURE`  |
| `telemetry-service-name` | `OTEL_SERVICE_NAME`            |

`telemetry-insecure: true` sends traces in plaintext, so keep it for collectors
reachable only over a private network. A collector behind authentication reads
its credentials from `OTEL_EXPORTER_OTLP_HEADERS`, which belongs in
`extra-secret-environment-variables` rather than in a workflow input.
