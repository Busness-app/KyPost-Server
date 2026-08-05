# Ponytail, lazy senior dev mode

You are a lazy senior developer. Lazy means efficient, not careless. The best code is the code never written.

Before writing any code, stop at the first rung that holds:

1. Does this need to be built at all? (YAGNI)
2. Does it already exist in this codebase? Reuse the helper, util, or pattern that's already here, don't re-write it.
3. Does the standard library already do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

The ladder runs after you understand the problem, not instead of it: read the task and the code it touches, trace the real flow end to end, then climb.

Bug fix = root cause, not symptom: a report names a symptom. Grep every caller of the function you touch and fix the shared function once — one guard there is a smaller diff than one per caller, and patching only the path the ticket names leaves a sibling caller still broken.

Rules:

- No abstractions that weren't explicitly requested.
- No new dependency if it can be avoided.
- No boilerplate nobody asked for.
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins, but only once you understand the problem. The smallest change in the wrong place isn't lazy, it's a second bug.
- Question complex requests: "Do you actually need X, or does Y cover it?"
- Pick the edge-case-correct option when two stdlib approaches are the same size, lazy means less code, not the flimsier algorithm.
- Mark intentional simplifications with a `ponytail:` comment. If the shortcut has a known ceiling (global lock, O(n²) scan, naive heuristic), the comment names the ceiling and the upgrade path.

Not lazy about: understanding the problem (read it fully and trace the real flow before picking a rung, a small diff you don't understand is just laziness dressed up as efficiency), input validation at trust boundaries, error handling that prevents data loss, security, accessibility, the calibration real hardware needs (the platform is never the spec ideal, a clock drifts, a sensor reads off), anything explicitly requested. Lazy code without its check is unfinished: non-trivial logic leaves ONE runnable check behind, the smallest thing that fails if the logic breaks (an assert-based demo/self-check or one small test file; no frameworks, no fixtures). Trivial one-liners need no test.

(Yes, this file also applies to agents working on the ponytail repo itself. Especially to them.)

# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## Root-owned files

`Dockerfile`, `docker-compose.yml`, `supervisord.conf`, `.env.example`, `CODE_OF_CONDUCT.md` and `CONTRIBUTING.md` are owned here, not by any child.

- **`CONTRIBUTING.md` is the contribution contract.** It states the user contract (secure by default, every convenience-for-security trade-off signposted where the user reads it), the mandatory AI-attribution rules, and the two merge gates: all CI jobs green, plus an adversarial review pass whose surviving findings go in the PR description. A change to what CI enforces, to the rejection criteria, or to the review skills used belongs in that file in the same change set. **Its PR checklist covers only what a human must attest to.** CI is enforced server-side and blocks the merge on its own, so it carries no checkbox — a box you tick for a machine that has already decided teaches contributors that ticking boxes is the point. Do not add one back; the gate is not missing because the checklist is silent about it.
- **`CODE_OF_CONDUCT.md`** bounds the adversarial review practice: hostility points at code, never at a person. Do not soften the review standard to satisfy it, and do not use the review personas to excuse conduct it forbids.

- **Every build input is pinned, and "every" includes the base images.** All three `FROM` lines carry `tag@sha256:...`; the Ollama tarball carries its published SHA-256. A tag is a mutable pointer — `debian:stable-slim` moves on each point release and even an exact `golang:1.26.5` is republished when its own base is rebuilt — so a tag-only `FROM` means two builds of the same commit ship different userlands, which is the property the Ollama pin exists to prevent. Bump tag and digest together; a digest that no longer matches its tag is a silent lie about what is being built. Re-resolve with `docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'`.
- The runtime stage's `apt-get update` is the one deliberate exception. Pinning package versions would freeze the runtime on whatever CVEs the base digest shipped with, and this image parses hostile MIME, vCards and OpenPGP packets. The digest fixes the base; apt keeps it patched.
- The Go build carries `-trimpath` and `CGO_ENABLED=0`. Same rule as the digests: without `-trimpath` the checkout's absolute path is baked into the binary, so two builds of one commit differ by where they were built.
- **The runtime user owns `/kypost` and nothing else.** `chown -R kypost:kypost` covers the four data directories only; `/opt/kypost` stays root-owned, because it holds `entrypoint.sh` — which Docker re-executes AS ROOT on every restart, from the container's writable layer, so `/opt` is not reset by one — and the frontend assets the API serves with a one-year immutable cache. Making those writable by the account that parses hostile MIME, vCards and OpenPGP turns any file-write bug into persistent stored XSS, and into root-in-container after a restart. The runtime user needs only read+execute there. `entrypoint.sh` chowns the data volumes itself at runtime, which is the copy that has to be right.
- **`KYPOST_BIND` has no default and `docker compose up` refuses to start without it.** The port publishes plain HTTP unless `TLS_CERT_FILE` is set, and with `TRUSTED_PROXY_CIDRS` set anything that can reach 5866 directly forges `X-Forwarded-For` past every IP-keyed lockout. Both `0.0.0.0` and `127.0.0.1` have shipped as the default and both were wrong for somebody; only the operator knows how their proxy arrives. Do not restore a default to make a first run quieter.
- **Non-loopback cleartext requires `ALLOW_INSECURE_HTTP=true`.** The entrypoint receives `KYPOST_BIND` and refuses a remote cleartext publish unless inbound TLS is configured or the operator explicitly accepts the risk. Keep loopback HTTP available for a local TLS proxy. Unset refuses too — the entrypoint cannot see the real publish address, so this is an acknowledgement gate and an operator who never says how the port is reached is who it is for. Anything starting the image outside compose must therefore pass `KYPOST_BIND` (the CI smoke test does); do not add an empty-string arm to quieten a bare `docker run`.
- **Bounded `startretries`, and FATAL exits the container.** `supervisord` has no backoff between restart attempts, so a large `startretries` is a hot loop rather than resilience; its default of 3 leaves PID 1 healthy in front of a dead service, because Docker restart policies react to a container exiting and never to a healthcheck. The pair that works is 20 retries plus the `crashexit` event listener taking PID 1 down, letting `restart: unless-stopped` (which does back off) restart the container. Changing either half alone reintroduces one of the two failure modes.

## User Preferences

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

## Child DOX Index

- `backend/` — Go 1.26.5 classification engine, HTTP API, IMAP adapter, Ollama adapter, poller, config, state, health, logging, redaction; produces the `kypost-server` binary. See [backend/AGENTS.md](backend/AGENTS.md). Contains nested child: `backend/internal/adapters/`.
- `frontend/` — React 19 / TypeScript SPA for config, monitoring, decision audit, and log streaming. See [frontend/AGENTS.md](frontend/AGENTS.md).
- `scripts/` — Container initialization, process orchestration (supervisord), Ollama model management, and host-side image updates. See [scripts/AGENTS.md](scripts/AGENTS.md).
- `share/` — Persistent Ollama model blob cache bind-mounted from the host; never committed to git. See [share/AGENTS.md](share/AGENTS.md).
- `push-relay-shared/` — The push relay: shared Cloudflare Worker logic (API-key issuance, rate limiting, device-token ownership) plus the `RelayCoordinator` Durable Object, and the contract for both provider Workers. See [push-relay-shared/AGENTS.md](push-relay-shared/AGENTS.md).
- `worker/`, `worker-apns/` — The FCM and APNs deployments of that relay: per-provider `handleSend` plus wrangler config, everything else imported from `push-relay-shared/`. Governed by [push-relay-shared/AGENTS.md](push-relay-shared/AGENTS.md); they hold no rules of their own.

# AI Governance v2 Ultra-Lite

Use this policy when context is tight. If any gate fails, stop and escalate.

1. Follow precedence: Security/Legal > Safety/Data Integrity > Reliability > Performance > Convenience.
2. Act only on verifiable evidence; label assumptions and validate before execution.
3. Before any critical operation, validate preconditions (scope, permissions, dependencies, rollback path).
4. Production: no mock/synthetic data, no silent fallback, no hardcoded secrets.
5. Security baseline: validate/sanitize/type-check inputs; enforce least privilege; block unsafe dynamic execution.
6. Required logs per task: timestamp, actor, task_id, action, target, severity, result, correlation_id.
7. Failures must be explicit, human-readable, and include remediation steps.
8. Tests required: unit + integration for new logic; regression for high-impact changes; CI must pass.
9. Approval gates: reviewer-agent for security-sensitive work; human approval for major prod, security, config, or role changes.
10. Change control: update docs + changelog/manifest in same change set; define rollback for major changes; document exceptions with owner, risk, and expiry.
