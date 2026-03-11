## tact

[![Unit tests](https://github.com/kordega/tact/actions/workflows/ci.yaml/badge.svg)](https://github.com/kordega/tact/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/kordega/tact)](LICENSE)
[![OpenTofu supported](https://img.shields.io/badge/OpenTofu-supported-844FBA?logo=opentofu&logoColor=white)](https://opentofu.org/)
![Terraform not supported](https://img.shields.io/badge/Terraform-not_supported-red?logo=terraform&logoColor=white)

> [!WARNING]
> No Terraform support. [[1]]

[1]: https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license

### Binary checksum verification

The `tofu-setup` action automatically verifies the integrity of the installed OpenTofu binary on every run. The verification step:

1. Downloads the official `SHA256SUMS` file from the OpenTofu GitHub release.
2. Verifies the GPG signature on the `SHA256SUMS` file using the [OpenTofu public key](https://get.opentofu.org/opentofu.gpg).
3. Downloads the platform-specific distribution archive and verifies its checksum against `SHA256SUMS`.
4. Extracts the binary from the verified archive and compares its SHA256 with the installed binary.

This protects against supply-chain attacks and accidental file corruption.

Verification is enabled by default and can be disabled by setting `verify-checksum: 'false'`:

```yaml
- uses: kordega/tact/actions/tofu-setup@main
  with:
    tofu-version: 1.9.1
    verify-checksum: 'false'
```

The action outputs `tofu-checksum` (the SHA256 of the installed binary) and `checksum-verified` (`true` when verification passes).
