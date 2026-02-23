## tofu-actions

Composite GitHub Actions for OpenTofu workflows.

### tf-plan-comment

Summarize a tfplan file with [`tf-summarize`](https://github.com/dineshba/tf-summarize) and post it to the related pull request using [`thollander/actions-comment-pull-request`](https://github.com/thollander/actions-comment-pull-request).

Example assuming you already generated a tfplan and exposed it as `steps.plan.outputs.plan-file-path` (for example with the `tf-plan` action in this repository):

```yaml
- uses: limakzi/tofu-actions/src/tofu-plan-comment@main
  with:
    plan-file-path: ${{ steps.plan.outputs.plan-file-path }}
```
