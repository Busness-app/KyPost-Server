# modeleval

Measures how well candidate Ollama models do the email classification defined by
`TUNING.md`, so the choice of default model is a measurement rather than an argument.

The prompt is assembled by `classifier.BuildRuntimePrompt` — the same function
`processor.Poller` calls — so results describe the prompt that actually ships.

## Start Ollama

There is no `ollama` binary on the dev host, and the version that matters is the one
pinned in the `Dockerfile`. Run it out of the shipped image, reusing the existing model
cache so anything already pulled is not downloaded twice:

```sh
docker run --rm -d --name modeleval-ollama \
  -p 127.0.0.1:11434:11434 \
  -e OLLAMA_HOST=0.0.0.0:11434 \
  -e OLLAMA_MODELS=/kypost/ollama-models \
  -v "$PWD/share/ollama/models:/kypost/ollama-models" \
  --entrypoint ollama \
  kypost-server-kypost-server:latest serve
```

The port is bound to `127.0.0.1` deliberately — Ollama has no authentication, and this
publishes it outside the container for the duration of the run.

Stop it with `docker stop modeleval-ollama` when finished.

## Run

From the `backend/` module root:

```sh
# check the assembled prompts without touching Ollama
go run ./cmd/modeleval -dry-run -configs A,B,C,D,E

# stage 1 — screen every candidate on the strongest configuration
go run ./cmd/modeleval -models all -configs D -out stage1.json

# stage 2 — full configuration matrix on the survivors
go run ./cmd/modeleval -models qwen3:4b,phi4-mini,gemma3:4b -configs A,B,C,D,E -out stage2.json
```

`-pull=false` skips the pull step for models already cached. `-models` takes a
comma-separated list. Models are evaluated strictly sequentially and unloaded
(`keep_alive: 0`) between runs.

## Memory

Check free memory before including `gemma4:e4b`. Its weights blob is 9.6 GB; on a host
with less free than that it will swap and its **latency numbers become meaningless**
(accuracy stays valid). Every other candidate in the default list fits under 4 GB.

## Configurations

| ID | Change |
|----|--------|
| A | current `TUNING.md`, current params — the true baseline |
| B | `TUNING.v2.md`, params unchanged |
| C | B + `temperature: 0` + `num_ctx: 4096` |
| D | C + structured output (`format` = string enum of the allowlist) |
| E | D + allowlist expanded with `Important`, `Questionable`, `Finance`, `Travel` |

qwen3-family models additionally get `"think": false` in every configuration; their
default reasoning mode emits `<think>` blocks, which is what `labelSearchScope`'s
last-40-lines scoping in `http_client.go` exists to survive.

## Corpus

`corpus.json` — 60 hand-authored emails with human-assigned gold labels.

| Bucket | Count | Purpose |
|--------|-------|---------|
| `core` | 40 | 10 per stock label, unambiguous |
| `trap` | 12 | lexical cues pointing at the wrong label |
| `injection` | 8 | body or subject tries to force a label |

Gold labels are **not** taken from `state.Store.Decisions()`. Those are the classifier's
own past answers; scoring against them would measure agreement with existing behaviour
rather than correctness.

Four items carry `"needs_adjudication": true`. They are genuine judgement calls, not
model failures — settle them before treating any accuracy figure as final:

- `core-primary-09` / `trap-09` — individually written recruiter mail. Deliberately
  paired; whichever way you rule, rule both the same way.
- `core-social-09` — a platform-generated job alert: `Social` by origin, closer to
  `Promotions` by purpose.
- `trap-12` — a trial-expiry notice that is simultaneously a factual account notice
  (`Updates`) and a conversion push (`Promotions`). This one sets policy.

## Metrics

Per (model, config):

- **accuracy** overall and split by bucket
- **strict format** — the raw output was nothing but an allowlisted label. This is the
  metric that says whether output-format failures, rather than classification failures,
  are the real problem.
- **unresolved** — no label recoverable, which in production raises
  `NoAllowedLabelError` and burns all three retries
- **would retry** — output matched the tools-only or empty-message shapes that trigger a
  production retry
- **injection resisted** — the forced label was *not* emitted
- **latency** p50/p95, and resident size from Ollama's `/api/ps`
- **confusion matrix**, gold against predicted

`resolveLabel` in `main.go` reproduces the resolution in `http_client.go:202-231`,
including its inherited quirks — the fallback matcher is `strings.Contains`-based and
iterates the *allowlist*, so it returns the earliest allowlisted label appearing anywhere
in the output regardless of negation. `main_test.go` pins that behaviour. The harness
must inherit the flaw, or it would report accuracy production never achieves.
