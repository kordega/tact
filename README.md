## tofu-actions

Composite GitHub Actions for OpenTofu workflows.

### tofu-plan-comment

Summarize a tfplan file with [`tf-summarize`](https://github.com/dineshba/tf-summarize) and post it to the related pull request using [`thollander/actions-comment-pull-request`](https://github.com/thollander/actions-comment-pull-request).

Example assuming you already generated a tfplan and exposed it as `steps.plan.outputs.plan-file-path` (for example with the `tf-plan` action in this repository):

```yaml
- uses: limakzi/tofu-actions/src/tofu-plan-comment@251c73571a98b1967b8f86d4e2d0ed60d541bd7e # pin to a specific ref
  with:
    plan-file-path: ${{ steps.plan.outputs.plan-file-path }}
```
