## tact

[![Unit tests](https://github.com/kordega/tact/actions/workflows/ci.yaml/badge.svg)](https://github.com/kordega/tact/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/kordega/tact)](LICENSE)
[![OpenTofu supported](https://img.shields.io/badge/OpenTofu-supported-844FBA?logo=opentofu&logoColor=white)](https://opentofu.org/)
![Terraform not supported](https://img.shields.io/badge/Terraform-not_supported-red?logo=terraform&logoColor=white)

> [!WARNING]
> No Terraform support. [[1]]

[1]: https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license

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
