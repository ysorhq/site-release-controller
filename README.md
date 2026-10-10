# site-release-controller

Independent production release controller for the Yevgeniy Sorokin site.

This public repository contains release-controller code and safe fixtures only. It must never contain private source from `ewgenij87snwork/yevgeniy-sorokin`.

Canonical architecture rationale is private ADR-0001 in `ewgenij87snwork/gpt-codex`.

Current state: controller core bootstrapped. Production enforcement remains blocked until the no-bypass main ruleset, source-read GitHub App credentials, production environment credentials, and Cloudflare-exclusive ingress are configured and proven.
