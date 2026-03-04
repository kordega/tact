variable "name" {
  type    = string
  default = "world"
}

output "greeting" {
  value = "hello ${var.name}"
}
