terraform {
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
  }
}

variable "encryption_passphrase" {
  description = "The passphrase used to derive the keys for OpenTofu state and plan encryption (pbkdf2)."
  type        = string
  sensitive   = true
}
