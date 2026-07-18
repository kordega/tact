terraform {
  encryption {
    # Test fixture only.
    key_provider "pbkdf2" "plan" {
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

  backend "s3" {
    bucket = "tofu-state"
    key    = "terraform.tfstate"
    region = "us-east-1"

    endpoints = {
      s3 = "http://127.0.0.1:9000"
    }

    access_key = "minioadmin"
    secret_key = "minioadmin"

    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    use_path_style              = true
    skip_s3_checksum            = true

    use_lockfile = true
  }
}
