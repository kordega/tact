# Copilot instructions for tact

This repository provides composite OpenTofu GitHub Actions under `actions/`,
reusable workflows under `.github/workflows/skeleton-*.yaml`, and rego
policies under `policies/`.

## Description style for inputs, outputs, and secrets (required)

Every `description:` field of an input, output, or secret — in every
`actions/*/action.yml` and in every `workflow_call` block of
`.github/workflows/*.yaml` — MUST follow this format:

1. Always use a YAML literal block scalar (`description: |`), even for a
   single-sentence description.
2. Put every sentence on its own separate line, ending with a period.
3. Never leave trailing whitespace on any line.
4. The first line states what the input, output, or secret is or does.
5. If the field has a `default:`, the last line of the description states it
   as `Defaults to <value>.`. Boolean string inputs state
   `Accepts true/false. Defaults to <value>.` on one line.

Canonical example:

```yaml
tofu-init-backend:
  description: |
    Whether to initialize the backend during tofu init.
    Accepts true/false. Defaults to true.
  required: false
  default: "true"
```

Bad — single-line scalar, multiple sentences on one line, default unstated:

```yaml
tofu-init-backend:
  description: Whether to initialize the backend during tofu init. Accepts true/false.
  required: false
  default: "true"
```

When generating or reviewing any change that touches an `action.yml` or a
workflow file, always check that every `description:` field is set up this
way. Fix deviations in generated code; flag deviations in reviews.
