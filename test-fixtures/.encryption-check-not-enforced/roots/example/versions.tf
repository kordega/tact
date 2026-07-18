terraform {
  required_version = ">= 1.12.4"

  backend "s3" {
    bucket = "tofu-state"
    key    = "roots/example/terraform.tfstate"
  }

  encryption {
    key_provider "pbkdf2" "plan" {
      passphrase = var.encryption_passphrase
    }

    method "aes_gcm" "plan" {
      keys = key_provider.pbkdf2.plan
    }

    plan {
      method   = method.aes_gcm.plan
      enforced = false
    }
  }
}

variable "encryption_passphrase" {
  description = "The passphrase used to derive the key for OpenTofu plan encryption (pbkdf2)."
  type        = string
  sensitive   = true
}
