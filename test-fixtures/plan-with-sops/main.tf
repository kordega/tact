variable "sops_secret_file" {
  description = "Path to the SOPS-encrypted secrets file."
  type        = string
  default     = "${path.module}/secret.sops.yaml"
}

data "sops_file" "secrets" {
  source_file = var.sops_secret_file
}

resource "terraform_data" "from_secret" {
  input = data.sops_file.secrets.data["secret_value"]
}

output "sops_secret_value" {
  value     = data.sops_file.secrets.data["secret_value"]
  sensitive = true
}
