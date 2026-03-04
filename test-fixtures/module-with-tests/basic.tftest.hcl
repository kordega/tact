run "uses_default_name" {
  command = plan

  assert {
    condition     = output.greeting == "hello world"
    error_message = "Expected default greeting to be hello world."
  }
}
