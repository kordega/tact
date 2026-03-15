# plan-with-sops-var test fixture

This fixture demonstrates reading a random SOPS-encrypted variable through the SOPS provider.

- `main.tf` uses a variable `random_secret` to select which key to read from the SOPS file.
- `secret.sops.yaml` contains a random encrypted value under the key `random_value`.
- Pass the variable `random_secret` with value `random_value` to read the secret.

Example usage:

```
tofu plan -var="random_secret=random_value"
```
