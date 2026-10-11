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

Normal PRs cannot mutate the protected controller surface.

Maintenance authorization is carried by an exact GitHub PR Conversation comment from `ewgenij87snwork`, not by a commit in `main`. The trusted-base gate accepts only a two-line comment: first `CONTROLLER_MAINTENANCE_V1`, then one compact JSON object binding exact `head_sha`, exact `protected_surface_sha256`, exact sorted `changed_paths`, an `expires_at_epoch` no more than four hours ahead, and a non-empty `reason`.

Because authorization lives outside the candidate branch and does not mutate `main`, strict up-to-date required checks remain enabled. Any candidate push changes the HEAD and invalidates the authorization immediately. Candidate code receives no write-capable token and cannot create its own trusted authorization comment.

Protected controller surface includes every file under `.github/workflows/**` plus `controller/workflow_surface_gate.py` and `controller/release_controller.py`.

## GPT Cloud bootstrap bundle

`.github/workflows/gpt-cloud-bootstrap.yml` prepares bytes; it is not CI and cannot mint a CI PASS. It runs only from protected `main` with `source-read`, verifies exact private HEAD/tree through the GitHub API, retains only package metadata long enough to populate dependency bytes, revokes the source token before package execution, downloads the pinned Playwright Chromium runtime, and uploads only the source-free Node/npm-cache/browser archive plus digest. GPT cloud independently verifies and consumes that bundle offline.


### Bootstrap v2 trust boundary

Bootstrap v2 never checks out the private repository. A short-lived read-only App token is exposed only to one trusted metadata-fetch shell step, which verifies the exact commit/tree and downloads only root `package.json` plus `package-lock.json`, then revokes the token. Dependency installation uses `npm ci --ignore-scripts` only after token revocation. The package metadata files are removed before Playwright package code is executed. The uploaded artifact contains only exact Node runtime bytes, npm cache content-addressed bytes, Playwright Chromium runtime bytes, a manifest and SHA-256; no private source or Git metadata.


## Release v1 fail-closed state

The original release workflow is intentionally disabled. A workflow dispatch now fails explicitly with `RELEASE_ENFORCEMENT_BLOCKED`; both legacy `verify-source` and `deploy` jobs are disabled. Reason: candidate-controlled scripts/composite action currently execute in the same runner context before trusted manifest admission. Release v2 must isolate candidate execution from trusted verifier state before any verify/deploy path can be re-enabled.


## Encrypted GPT cloud source bridge

Private source is never uploaded as plaintext from the public controller. A bootstrap request may carry an ephemeral GPT-cloud X.509 recipient certificate (public material only). Trusted protected `main` then reads the exact private commit with a short-lived read-only App token, verifies HEAD/tree, archives tracked bytes without executing candidate code, explicitly revokes the token, deletes the checkout, encrypts the source archive with CMS AES-256-GCM to the ephemeral recipient, deletes plaintext, and uploads only ciphertext chunks plus public digests. GPT cloud retains the private key, verifies artifact/cipher/plaintext digests after decryption, reconstructs the Git tree, and only then starts PRIMARY CI.
