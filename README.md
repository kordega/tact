## tofu-actions

Composite GitHub Actions for OpenTofu workflows.

### tf-plan-comment

Summarize a tfplan file with [`tf-summarize`](https://github.com/dineshba/tf-summarize) and post it to the related pull request using [`thollander/actions-comment-pull-request`](https://github.com/thollander/actions-comment-pull-request).

```yaml
- uses: limakzi/tofu-actions/src/tofu-plan@main
  id: plan
  with:
    environment: dev

- uses: limakzi/tofu-actions/src/tofu-plan-comment@main
  with:
    plan-file-path: ${{ steps.plan.outputs.plan-file-path }}
```
