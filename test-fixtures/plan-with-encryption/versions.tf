terraform {
  required_version = ">= 1.12.0"

  encryption {
    key_provider "pbkdf2" "plan" {
      # Test fixture only.
      passphrase = "tact-test-fixture-passphrase"
    }

    method "aes_gcm" "plan" {
      keys = key_provider.pbkdf2.plan
    }

    plan {
      method   = method.aes_gcm.plan
      enforced = true
    }
  }
}
