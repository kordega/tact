run "plan_has_no_changes" {
  command = plan

  assert {
    condition     = length(plan.resource_changes) == 0
    error_message = "expected no resource changes"
  }
}
