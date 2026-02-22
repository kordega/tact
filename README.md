## tofu-actions

[![Tests](https://github.com/limakzi/tofu-actions/actions/workflows/continuous-integration.yaml/badge.svg)](https://github.com/limakzi/tofu-actions/actions/workflows/continuous-integration.yaml)
[![Test Files](https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/limakzi/tofu-actions/contents/tst&label=test%20files&query=length(%24[?(@.name%3D~%2F\\.tf%24%2F)])&color=blue)](./tst)

The test count badge reads the number of `.tf` test files under `tst/` from the GitHub contents API when the page loads, updating as files change subject to GitHub caching and unauthenticated rate limits.
