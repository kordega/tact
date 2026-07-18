terraform {
  required_version = ">= 1.12.4"

  backend "s3" {
    bucket = "tofu-state"
    key    = "roots/example/terraform.tfstate"
  }

  encryption {
    plan {
      method   = method.aes_gcm.plan
      enforced = true
    }
  }
}
