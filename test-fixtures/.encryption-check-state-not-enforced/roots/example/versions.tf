terraform {
  required_version = ">= 1.12.4"

  backend "s3" {
    bucket = "tofu-state"
    key    = "roots/example/terraform.tfstate"
  }

  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.encryption_passphrase
    }

    key_provider "pbkdf2" "plan" {
      passphrase = var.encryption_passphrase
    }

    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }

    method "aes_gcm" "plan" {
      keys = key_provider.pbkdf2.plan
    }

    state {
      method   = method.aes_gcm.state
      enforced = false
    }

    plan {
      method   = method.aes_gcm.plan
      enforced = true
    }
  }
}

variable "encryption_passphrase" {
  description = "The passphrase used to derive the keys for OpenTofu state and plan encryption (pbkdf2)."
  type        = string
  sensitive   = true
}
