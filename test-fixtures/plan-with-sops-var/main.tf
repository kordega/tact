variable "random_secret" {
  description = "A random secret value encrypted with SOPS."
  type        = string
}

data "sops_file" "secrets" {
  source_file = "${path.module}/secret.sops.yaml"
}

resource "terraform_data" "from_secret" {
  input = data.sops_file.secrets.data["${var.random_secret}"]
}

output "sops_secret_value" {
  value     = data.sops_file.secrets.data["${var.random_secret}"]
  sensitive = true
}
