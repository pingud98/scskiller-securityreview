# SCSKiller Security Review

Independent, three-model security review of **SCSKiller** (Shader Compilation Stutter Killer) — a free,
open-source Windows desktop tool that pre-compiles game shaders into the GPU driver cache, plus its
native proxy/recorder components.

- **Date of review:** 2026-10-11
- **SCSKiller commit reviewed:** `bf2571af3db4d1d3c49aeb05cda170571eae0704`
- **SCSKiller version/tag:** v1.2.5
- **Upstream repository:** https://github.com/BlueHeisenberg/SCSKiller
- **Review models:**
  - `deepseek-v4-flash` — default model
  - `longcat-2.5-preview-free` — long-context comparison
  - `kimi-k3` — third comparison

## What was reviewed

The security-relevant surface of the v1.2.5 tree was extracted and audited in four chunks:

1. **Update system** — `src/SCSKiller.Core/App/Updates.cs`, `src/SCSKiller.App/Updater.cs`, `src/SCSKiller.Core/App/AppStore.cs`
2. **Download / fetch / game-file handling** — `src/SCSKiller.Core/Games/GameFiles.cs`, `src/SCSKiller.Core/Games/ReShade.cs`, `src/SCSKiller.Core/Carved/CarvedReader.cs`
3. **Auth / tokens / CLI** — `src/SCSKiller.Core/App/ScsKiller.Offline.cs`, `src/SCSKiller.Cli/Program.cs`
4. **Native proxy (C++) + release tooling** — `proxy/warm.cpp`, `proxy/warm11.cpp`, `proxy/vtslots.cpp`, `proxy/vk_spirv.py`, `tools/release-sign/Program.cs`

Each model received the same audit brief: a threat model (local attacker influencing the update feed,
game-supplied shader containers, the injected game process, and network responses), a strict finding
schema, and a severity rubric. Raw returns are preserved verbatim under `reviews/`.

## TL;DR

- **All three models independently flagged the update/feed chain** (signature trust, replay/freshness,
  download limits) and **path/junction handling** as the highest-risk areas.
- **The native C++ proxy/warmer** (`warm.cpp`, `warm11.cpp`) is where the most *exploitable* issues
  concentrate: untrusted shader bytecode (DXBC) is parsed with unchecked offsets and drives D3D view
  creation inside the game process.
- **No clear-cut Remote Code Execution chain from an internet attacker alone** was identified by any
  model without additional assumptions (compromised feed signing key, or a malicious game already on
  the machine), but several findings approach it given the project's own threat model.
- Counts are **not comparable across models** — deepseek numbered 14 findings, longcat 12, kimi 10,
  with differing granularity and severity voting (kimi votes "critical" far more liberally).

## Synthesised findings (deduplicated across models)

> IDs are the raw model IDs preserved for traceability. **D** = deepseek-v4-flash, **L** = longcat-2.5-preview-free, **K** = kimi-k3.

### Update & feed chain
- **Update feed/package trust anchor is a pair of hardcoded Ed25519 keys with no rotation or revocation** — standard pinning, but the sole root of trust. `Updates.cs` `FeedTrust.ReleaseKeys`. *(K S1)*
- **Replay protection is a per-channel monotonic clock (`signed_at`) that the attacker controls via the network; no freshness window enforced.** *(D S2, K S2/K S10)*
- **`StagedUpdate` validation order**: SHA-256 of the package checked by Velopack *after* the body is written; `Refused` may be satisfied with only a prior feed; record doesn't enforce that the feed for the package's own channel is present. *(D S3/S4/S8, K S3)*
- **Cross-channel merge** (`SignedFeedSource.GetReleaseFeed`) has no cross-channel version-conflict detection. *(K S9, D S4)*
- **Unbounded feed body download** — `FeedClient.GetAsync` reads the whole body with no byte limit before signature verification (memory-exhaustion DoS by feed host/MITM). *(L S1)*
- **No TLS certificate pinning** — downloads rely purely on platform validation. *(L S2)*
- **`SCSKILLER_API` / package-host environment variable can redirect package downloads** to an arbitrary host on non-stable channels, bypassing the "packages hosted by name" assumption. *(D S6, K S4)*
- **Bearer access token sent to any non-stable URL including redirect targets** (`FeedClient.SendAsync`); RouteFailover not shown to strip it. *(D S7, K S3-revised)*

### Path / junction / traversal
- **`AppStore.Resolve` copies any file under the portable `data\` tree without sanitising relative paths; a pre-created directory can trigger the "stale" rename.** *(D S5)*
- **`AppStore.GameDir` `GameId` unescape is unsanitised** and can yield a folder name escaping the intended tree. *(D S9, K S5 — case-insensitive/Unicode-normalisation bypass)*
- **"Is this inside the install" checks only inspect the target file or miss reparse points**, letting a malicious game folder make SCSKiller read/stage files outside the intended tree (junction/symlink). *(D S3, L S3)*

### Native proxy / warmer (C++) — in-game-process risk
- **`warm11.cpp` parses attacker-controlled DXBC from `scskiller.db` with unchecked indices/offsets/lengths.** *(L chunk4 S1)*
- **Malformed DXBC resource declarations (dim/ret/samples/extra) drive D3D11 view creation.** *(L chunk4 S6)*
- **`--d3d12` path used without canonicalisation; DLL search order for staged proxy / Agility SDK** via `LoadLibraryW(dir + "d3d12.dll")` in the child. *(L chunk4 S1–S2, S5)*
- **On the packaged branch the `d3d12.dll` proxy is loaded by the child *before* signature verification of the staged proxy.** *(L chunk4 S4)*
- **`partner_vs()` builds HLSL from untrusted signature/declaration names** and treats it as trusted source. *(L chunk4 S2)*
- **`--package` passes user-controlled `exe` path and args to `IDesktopAppXActivator`.** *(L chunk4 S3)*
- **Warm re-add-on staging**: add-on/loader files copied into staging purely by name + weak heuristic; a malicious file next to the game is staged and loaded into the game process; no hash/signature check from game-supplied ini paths. *(D S1/S5)*

### State, locking, auth
- **`Busy.Hold` returns a `Mutex(false, name)` that is never acquired** — compile/update mutual-exclusion gate is effectively empty (TOCTOU between update apply and active cache writes). *(D S1, K S6/S7)*
- **Probe/identity cache trusts size+mtime+file-id and caches security-relevant verdicts across runs.** *(D S4)*
- **`SaveProbes`/on-disk state is non-transactional and written with attacker-influenceable content.** *(D S6)*
- **`PathGate` lock file created in the same directory as the locked file** (lock-file planting). *(K S7)*
- **Release-sign tool** silently overwrites/accepts a key file outside git via a non-cryptographic side channel; `verify` advises but does not enforce. *(D S1/S2 in tools chunk)*

### Unverified observations / further work
- The Velopack integration (`Updates.cs` `DownloadUpdate`, staged-package apply) was reviewed by source only; a deeper look at `VelopackApp`/`UpdateManager` behaviour and the exact Velopack signature check would confirm the "after-write" ordering.
- The full `ScsKiller.cs` (5546 lines, the main orchestrator) was **not** in the audit corpus — only its offline/auth slice and the classes above. A follow-up should cover the remaining surface.
- `proxy/warm.cpp`, `warm11.cpp` warrant a dedicated fuzzing pass with malformed DXBC/PDB inputs; the parsers are hand-rolled and unchecked.
- The on-disk `scskiller.db` format and whether a game can plant entries that get executed at "warm" time is worth a focused review.

## Raw reviews

- [deepseek-v4-flash](reviews/deepseek-v4-flash.md) — 14 findings
- [longcat-2.5-preview-free](reviews/longcat-2.5-preview-free.md) — 12 findings
- [kimi-k3](reviews/kimi-k3.md) — 10 findings

## Method notes

- Cloned at the pinned commit (`--depth 1`, no submodules).
- Same corpus, same prompt, same chunking for all three models; `thinking` blocks were disabled for
  deepseek and kimi so the final answer appears in the text block (longcat emits content natively).
- Raw outputs are exactly as returned, unmodified, chunk-merged.
- Findings summary is my own cross-model synthesis on top of the three raw returns — read the raw
  reviews for full detail and the models' own caveats.

## Repo provenance

- Review performed: 2026-10-11 07:18 UTC
- SCSKiller commit: `bf2571af3db4d1d3c49aeb05cda170571eae0704` (2026-10-10, "SCSKiller v1.2.5")
- This review targets **only** that commit; later upstream changes are not covered.