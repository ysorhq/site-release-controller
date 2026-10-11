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


## Workflow maintenance

Normal PRs cannot mutate `.github/workflows/**`.

Future workflow maintenance is content-addressed:
1. prepare the workflow-change PR and freeze its exact HEAD;
2. let the trusted workflow-surface gate report the exact candidate workflow snapshot digest and changed paths;
3. merge a separate non-workflow authorization entry into `maintenance/workflow-authorizations.json` on trusted `main`;
4. rerun the maintenance PR; the gate reads only trusted-main authorization and accepts only the exact authorized HEAD + protected-surface digest + changed paths;
5. any push changes the HEAD/digest and fails closed.

After this bootstrap transition, normal workflow maintenance no longer requires disabling repository rules.

## GPT Cloud bootstrap bundle

`.github/workflows/gpt-cloud-bootstrap.yml` prepares bytes; it is not CI and cannot mint a CI PASS. It runs only from protected `main` with `source-read`, verifies exact private HEAD/tree, runs `npm ci --ignore-scripts` only to populate dependency bytes, downloads the pinned Playwright Chromium runtime, packages exact Node/npm-cache/browser bytes, deletes private source, and uploads only the source-free archive plus digest. GPT cloud independently verifies and consumes that bundle offline.


Protected controller surface includes every file under `.github/workflows/**` plus `controller/workflow_surface_gate.py` and `controller/release_controller.py`. The authorization registry itself is deliberately outside that digest so a separate non-workflow trusted-main PR can authorize an exact frozen maintenance candidate.
