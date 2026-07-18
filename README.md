## tact

[![Unit tests](https://github.com/kordega/tact/actions/workflows/ci.yaml/badge.svg)](https://github.com/kordega/tact/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/kordega/tact)](LICENSE)
[![OpenTofu supported](https://img.shields.io/badge/OpenTofu-supported-844FBA?logo=opentofu&logoColor=white)](https://opentofu.org/)
![Terraform not supported](https://img.shields.io/badge/Terraform-not_supported-red?logo=terraform&logoColor=white)

> [!WARNING]
> No Terraform support. [[1]]

[1]: https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license

## Usage

### `skeleton-root-checks.yaml`

```yaml
root-checks:
  strategy:
    fail-fast: false
    matrix:
      environment:
        - prd-tfstate
        - prd-cloudflare-dns
        - prd-github-organization
      include:
        - environment: prd-tfstate
          require-tofu-version-file: false
  uses: kordega/tact/.github/workflows/skeleton-root-checks.yaml@main
  with:
    chroot-directory: roots/${{ matrix.environment }}
    require-tofu-version-file: ${{ matrix.require-tofu-version-file || true }}
    require-lock-file: true
```
