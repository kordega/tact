run "plan_has_changes" {
  command = plan

  assert {
    condition     = length(plan.resource_changes) == 1
    error_message = "expected a single resource change"
  }
}
