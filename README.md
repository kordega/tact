## tact

[![Unit tests](https://github.com/kordega/tact/actions/workflows/ci.yaml/badge.svg)](https://github.com/kordega/tact/actions/workflows/ci.yaml)
[![License](https://img.shields.io/github/license/kordega/tact)](LICENSE)
[![OpenTofu supported](https://img.shields.io/badge/OpenTofu-supported-844FBA?logo=opentofu&logoColor=white)](https://opentofu.org/)
![Terraform not supported](https://img.shields.io/badge/Terraform-not_supported-red?logo=terraform&logoColor=white)

> [!WARNING]
> No Terraform support. [[1]]

[1]: https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license

### Actions

#### `binary-checksum`

Verify the checksum and optional GPG signature of a binary file. Protects against supply-chain attacks and accidental file corruption.

##### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `file` | yes | | Path to the binary file to verify. |
| `algorithm` | no | `sha256` | Hash algorithm (`sha256`, `sha512`, `sha1`, `md5`). |
| `checksum` | no | | Expected checksum value. Mutually exclusive with `checksum-file`. |
| `checksum-file` | no | | Path to a checksum file (e.g. `SHA256SUMS`). Mutually exclusive with `checksum`. |
| `signature-file` | no | | Path to a GPG detached signature file (`.sig`/`.asc`). Requires a public key input. |
| `public-key-file` | no | | Path to a GPG public key file for signature verification. |
| `public-key-url` | no | | URL to download the GPG public key for signature verification. |

##### Outputs

| Name | Description |
|------|-------------|
| `checksum` | Computed checksum of the file. |
| `checksum-verified` | `true` if checksum matched the expected value, `false` on mismatch. Empty when no expected checksum was provided. |
| `signature-verified` | `true` if the GPG signature was verified, `false` on failure. Empty when no signature file was provided. |

##### Usage

Verify a downloaded binary against an expected SHA256 checksum:

```yaml
- uses: kordega/tact/actions/binary-checksum@main
  with:
    file: my-binary
    checksum: "abc123..."
```

Verify using a checksum file and GPG signature:

```yaml
- uses: kordega/tact/actions/binary-checksum@main
  with:
    file: my-binary
    checksum-file: SHA256SUMS
    signature-file: my-binary.sig
    public-key-file: release-key.pub
```
