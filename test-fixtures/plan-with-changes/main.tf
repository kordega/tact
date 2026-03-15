resource "time_static" "this" {}

output "rfc3339" {
  value = time_static.this.rfc3339
}
