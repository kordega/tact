terraform {
  backend "http" {
    address        = "http://127.0.0.1:18080/state"
    lock_address   = "http://127.0.0.1:18080/state"
    unlock_address = "http://127.0.0.1:18080/state"
  }
}
