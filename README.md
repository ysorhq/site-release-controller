# site-release-controller

Independent production release controller for the Yevgeniy Sorokin site.

This public repository contains release-controller code and safe fixtures only. It must never contain private source from `ewgenij87snwork/yevgeniy-sorokin`.

Canonical architecture rationale is private ADR-0001 in `ewgenij87snwork/gpt-codex`.

Current state: controller core bootstrapped. Production enforcement remains blocked until the no-bypass main ruleset, source-read GitHub App credentials, production environment credentials, and Cloudflare-exclusive ingress are configured and proven.


## Source-read environment bootstrap

The `source-read` environment is intentionally separate from `production`.

Required environment configuration:
- variable `PRIVATE_SOURCE_APP_ID`: GitHub App ID; not secret.
- variable `WEBMCP_ORIGIN_TRIAL_TOKEN`: public Origin Trial token used in response headers; not treated as a credential.
- secret `PRIVATE_SOURCE_APP_PRIVATE_KEY`: private key for the repository-scoped source-reader GitHub App.

The source-reader GitHub App must be installed only on `ewgenij87snwork/yevgeniy-sorokin` with repository Contents: read-only and no webhook subscriptions.
