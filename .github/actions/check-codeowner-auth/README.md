# check-codeowner-auth

Authorizes `pull_request_target` and `pull_request_review` workflow runs by checking whether the PR author or a reviewer is a member of a team listed in the repository's `CODEOWNERS` file.

Designed as a **programmatic substitute** for the manual GitHub `environment: <name>` approval gate on privileged workflows. Same trust decision (a codeowner has authorized this run), enforced automatically.

## Trust boundary

**This action is a security gate. It must be used correctly to be safe. Read this section before adopting.**

The action MUST run in a job that:

1. Is triggered by `pull_request_target` or `pull_request_review`.
2. Contains **no other steps that execute PR-controlled code.** Specifically:
   - No `actions/checkout` (the default checks out the PR head).
   - No `uses: ./<path>` (local actions live in the PR).
   - No `run:` steps that interpolate `${{ github.event.pull_request.* }}` or `${{ github.head_ref }}` into shell commands.
3. Has minimal `permissions:` — the App token is passed via `inputs.github-token`, not via `GITHUB_TOKEN`.

Downstream (privileged) jobs MUST:

1. Declare `needs: authorize` so they only run when the gate passes.
2. Pin `actions/checkout` to `${{ needs.authorize.outputs.head-sha }}`. **Never** use `github.head_ref` (branch name, re-resolves at checkout time) or `refs/pull/<n>/merge` (re-merges live). Failing this rule allows a mid-run force-push to slip untrusted code through the gate.
3. Not receive the App token — it is scoped to the authorize job only.

## Inputs

| Input | Required | Description |
|:--|:--|:--|
| `github-token` | yes | Installation token from a GitHub App with `Members: Read` and `Contents: Read` on the org. Do NOT pass `GITHUB_TOKEN` — it lacks the org-team scope. |
| `trusted-bot-ids` | no | Comma-separated numeric GitHub user IDs (not logins) of bots always authorized as PR authors. Each is verified to have `user.type === 'Bot'` at runtime. |

## Outputs

| Output | Description |
|:--|:--|
| `head-sha` | The vetted PR head commit SHA. Downstream `actions/checkout` MUST pin to this value. |

## Recommended workflow pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
  pull_request_review:
    types: [submitted]

permissions: {}

jobs:
  authorize:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      head-sha: ${{ steps.gate.outputs.head-sha }}
    steps:
      - uses: actions/create-github-app-token@<full-40-char-sha>  # pin to SHA
        id: app-token
        with:
          app-id: ${{ vars.AUTH_GATE_APP_ID }}
          private-key: ${{ secrets.AUTH_GATE_PRIVATE_KEY }}
      - uses: kyma-project/actions/.github/actions/check-codeowner-auth@<full-40-char-sha>
        id: gate
        with:
          github-token: ${{ steps.app-token.outputs.token }}

  privileged-job:
    needs: authorize
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<full-40-char-sha>
        with:
          ref: ${{ needs.authorize.outputs.head-sha }}   # pin to vetted SHA
      # … privileged work …
```

## CODEOWNERS requirements

- Only `@<org>/<team>` entries are counted. Individual GitHub handles (e.g. `@someuser`) are ignored with a warning.
- Only teams in the **same org** as the repository are counted. `@other-org/team` entries are ignored.
- Repositories that use individual-handle CODEOWNERS must migrate to teams before adopting this gate.
- The file is read from the **base ref** via the GitHub REST contents API, not the runner filesystem. A PR that modifies CODEOWNERS in its head branch does not affect the gate's decision.
- Missing / empty / team-less CODEOWNERS files cause the action to fail closed.

## Authorization logic

```mermaid
flowchart TD
  A[Event received] --> B{Event is pull_request_target<br/>or pull_request_review?}
  B -- no --> FAIL[setFailed: unsupported event]
  B -- yes --> C{Author id in trusted-bot-ids<br/>AND user.type == Bot?}
  C -- yes --> PASS[authorized]
  C -- no --> D[Fetch CODEOWNERS from base ref]
  D --> E{CODEOWNERS has<br/>@org/team entries?}
  E -- no --> FAIL2[setFailed: no team codeowners]
  E -- yes --> F{Author is active member<br/>of any codeowner team?}
  F -- yes --> PASS
  F -- no --> G[Find approvals at current HEAD SHA<br/>filter: user.type=User AND user != author]
  G --> H{Any approval submitted<br/>by active team member?}
  H -- yes --> PASS
  H -- no --> FAIL3[setFailed: no codeowner approval]
```

## Design notes

Documented for reviewers and future maintainers. If you're changing this action, read these first.

### Why base-ref CODEOWNERS, not workspace

On `pull_request_target`, a naive `actions/checkout` writes the PR-HEAD version of the repo to the workspace. Reading `CODEOWNERS` from disk would then read the attacker's version. The action fetches from the base ref via the contents API so this is not possible.

### Why `state === 'active'` on team membership

`GET /orgs/{org}/teams/{team}/memberships/{user}` returns 200 with `state: 'pending'` for outstanding invitations that the user has not accepted. Treating "didn't 404" as "is a member" would authorize attackers who have been sent an invite but never accepted it. The action requires `state === 'active'`.

### Why numeric bot IDs, not logins

GitHub usernames can be recreated after deletion. A trusted-bot allowlist keyed by login would break the moment `renovate[bot]` is deleted and re-registered. Numeric user IDs are stable. The allowlist also requires `user.type === 'Bot'` as defense-in-depth.

### Why the approver-not-author check

GitHub server-side blocks a PR author from approving their own PR with 422. Defense-in-depth: the action also filters `review.user.login !== pr.user.login` in case that server-side check is ever bypassed by a race or edge case.

### Why the approver-must-be-User check

If a bot account is ever added to a codeowner team (e.g. an "auto-approve trivial docs" bot), an attacker can craft a PR that trips the bot's heuristics and gets an approval. Rejecting `user.type === 'Bot'` on the approver side prevents this. Trusted bots are handled explicitly via the `trusted-bot-ids` input, not via team membership.

### Nested team semantics

`GET /orgs/{org}/teams/{team}/memberships/{user}` recurses into child teams. If someone nests a broader team under a codeowner team, its members transitively become codeowners. This is documented as intentional — nested teams are legitimate GitHub org structure. Maintainers of the codeowner teams should be aware.

### Codeowner scoping is global, not path-scoped

If any codeowner team owns any path in the repo, its members can authorize the whole run. This matches env-gate semantics (a human clicking "Approve" on the environment gate authorizes the whole run, not per-path). Path-scoped authorization is a future enhancement — it would require parsing which paths the PR touches and matching CODEOWNERS patterns.

## Required GitHub App permissions

- `Organization → Members: Read` — for team membership lookups.
- `Repository → Contents: Read` — for fetching CODEOWNERS from the base ref.

Install the App on a **Selected repositories** list, not org-wide. Rotate the private key on a schedule.

## Known limitations

- **No mid-run re-check.** Once a downstream job starts, it runs to completion regardless of subsequent approval dismissals. Same limitation as the manual env-gate.
- **No script-injection protection.** If a consumer workflow interpolates PR-controlled fields into `run:` blocks, the auth-gate cannot help. Workflow-file discipline is a separate concern.
- **No cross-org codeowner support.** `@other-org/team` entries in CODEOWNERS are ignored. The action only checks teams within the same org as the repository.
