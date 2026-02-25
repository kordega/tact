data "sops_file" "secrets" {
  source_file = "${path.module}/secret.sops.yaml"
}

resource "terraform_data" "from_secret" {
  input = data.sops_file.secrets.data["secret_value"]
}

output "sops_secret_value" {
  value = data.sops_file.secrets.data["secret_value"]
  sensitive = true
}
