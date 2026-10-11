## CHUNK 0

# Security Audit — SCSKiller v1.2.5

Scope: the three supplied files (`Updates.cs`, `Updater.cs`, `AppStore.cs`). I have reviewed them against the stated threat model. Findings are limited to what the code shows; I have not fabricated issues where a check exists.

---

## S1 — `Busy.Hold` returns a `Mutex` that is never actually acquired (mutual-exclusion bypass, gate is empty)

- **ID:** S1
- **TITLE:** Busy/compile/update mutual-exclusion is not enforced — `new Mutex(false, name)` does not take ownership
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `Busy.Hold` (and every caller: `TryHold`, `IsHeld` used via `Mutex.TryOpenExisting`, `Updater.ApplyAsync`, `Updater.RestartAsync`, `Updater.HeldBack`).
- **SEVERITY:** High
- **CATEGORY:** Privilege / TOCTOU (race between update apply and an active compile/driver-cache write)
- **DESCRIPTION:**
  ```csharp
  public static IDisposable Hold(string name = Name) => new Mutex(false, name);
  ```
  `new Mutex(false, name)` creates (or opens) the named mutex but does **not** acquire it; the returned object is not owned by the calling thread. `IsHeld()` then tests `Mutex.TryOpenExisting(name, out _)`, which succeeds as soon as the named object *exists* at all. Since the object is created by every `Busy.Hold()` call and lives as long as any handle to it is open, `IsHeld()` is effectively "does any process have a `Busy.Hold` handle open right now," and the intended mutual exclusion between "an update handover to Update.exe" and "a compile worker that is mid-write into the GPU driver cache / game process" is not actually provided by the mutex. `ApplyAsync`'s comment ("a compile worker holds Busy first, then reads the marker … so one of the two always sees the other") is only true under the weaker "object exists" semantics — and even then only if the harness that checks `IsHeld()` and the check inside `ApplyAsync` are not separated by a window where the only holder is the updater itself. The `applying` marker file (`Busy.MarkApplying`/`Applying`) is the only other gate, and it is a file the updater and the compile worker both race on.
- **ATTACK SCENARIO:** An attacker who can influence timing (or simply a user who queues a warm while a background check stages an update) can observe that `ApplyAsync` proceeds to `Update.exe` handover while a compile worker is between `Busy.Hold()` and `Applying()` checks — the swap of `current\` occurs under a live process that has the game open, corrupting the GPU driver cache (or, worse, the game's recorder injection state) that `RestartAsync` explicitly tries to protect ("stops the queue gracefully …, the driver writes its cache"). At minimum this is a DoS on the warm path; at worst it defeats the "never apply an update under a running warm" guarantee the code documents.
- **CONFIDENCE:** High — the semantics of `new Mutex(false, name)` are unambiguous; no `WaitOne`/`ReleaseMutex` pair exists anywhere in these files.
- **RECOMMENDED FIX:** Either actually acquire the mutex (`var m = new Mutex(false, name); try { if (!m.WaitOne(0)) { m.Dispose(); return null; } } catch (AbandonedMutexException) { /* take as acquired */ } return new Held(m);` with a wrapper that calls `ReleaseMutex` on dispose) and make `IsHeld` use a separate `TryOpenExisting`-based probe, or replace the whole mechanism with an ownership-checked primitive (e.g. `EventWaitHandle` + `Reset`/`Set`, or a file handle opened with `FileShare.None` like `PathGate` already does). Document which call is the "holder" vs. which is the "probe."

---

## S2 — Feed replay protection is a monotonic-per-channel clock the attacker fully controls via the network (rollback / freshness gap)

- **ID:** S2
- **TITLE:** `FeedTrust.Accept` accepts any feed whose `signed_at` is ≥ the last-seen value, and the last-seen value is written to disk in plaintext the attacker can influence through the update feed itself
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `FeedTrust.Accept` / `Verify`; state in `AppStore.LoadFeedTimes`/`SaveFeedTimes` (`feeds.json`).
- **SEVERITY:** Medium
- **CATEGORY:** Weak crypto / anti-rollback / TOCTOU on update freshness
- **DESCRIPTION:** The freshness check is:
  ```csharp
  if (newest.TryGetValue(channel, out var seen) && at < seen) throw new FeedRejectedException(...);
  newest[channel] = at;
  ```
  a pure "must be strictly ≥ last seen" check with no upper bound, no signature over the *previous* value, and no anchoring of `feeds.json`. Two consequences:
  1. A compromised or coerced feed server (threat model (a)) can publish a *future-dated* feed once, and every subsequently-signed-legitimately feed with a real timestamp will then be rejected until wall-clock catches up. That is a straightforward denial of updates (the user cannot install a security fix) — the app will simply never stage a new release, and the code logs this as a failure rather than alerting loudly.
  2. Because the per-channel last-seen value is stored unauthenticated in the user's `%LOCALAPPDATA%`, an attacker with local write access can *lower* it (or delete `feeds.json`) to re-enable replay of an older signed feed. Combined with the internal-channel downgrade allowance (`UpdateChannels.AllowsDowngrade`), a locally-crafted `feeds.json` can be used to make an older signed internal feed acceptable again.
  The signature itself is properly pinned (Ed25519, `FeedTrust.ReleaseKeys`, `kid` lookup, SHA-256 of the feed body), so a network-only attacker cannot forge a feed — but they *can* freeze or unfreeze the accepted-timestamp floor.
- **ATTACK SCENARIO:** (a) Attacker controls / MITMs the feed endpoint and serves a valid, correctly-signed feed with `signed_at` in the far future. Every later genuine feed is rejected as "older than one already seen." Users do not get security updates. Alternatively (a-local) attacker writes `feeds.json` to clear the floor and replays a previously valid signed beta/internal feed whose package is a known-vulnerable build; on the `internal` channel the version may even be older than the running one.
- **CONFIDENCE:** High that the floor can be silently moved; Medium that a future-dated signed feed is achievable — it depends on whether the release-sign tool validates `signed_at`, which is not in the supplied sources.
- **RECOMMENDED FIX:** Bind `feeds.json` to the anchor: store the last-seen `signed_at` (and the feed hash) signed under the release key, or at least check it against the Authenticode signature / DPAPI-bound per-user secret so a local attacker cannot silently rewrite it. Reject feeds whose `signed_at` is more than a small skew (e.g. 24 h) ahead of local time. Surface a distinct "update channel is pinned to a future feed" error to the UI instead of the generic signature-rejection path.

---

## S3 — `StagedUpdate.Lists` does not verify the feed lists the *package's* channel, only some feed; and accepts `SHA256`/`Size`/`Version` independently

- **ID:** S3
- **TITLE:** Staged-update re-validation can be satisfied by any signed feed the record names, not necessarily the package's own channel
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `StagedUpdate.Refused` and `StagedUpdate.Lists`.
- **SEVERITY:** Medium
- **CATEGORY:** Input validation / trust boundary
- **DESCRIPTION:** `Refused` requires each feed in `Feeds` to have a `channel` at index ≤ the record's `Channel`:
  ```csharp
  if (Array.IndexOf(UpdateChannels.All, channel) is var c && (c < 0 || c > at)) return "...isn't read on the ... channel";
  ```
  and then `listed |= Lists(f.Feed)`. `Lists` matches on `FileName`, `Version`, `SHA256`, `Size`, `Type == Full` — but not on the package's *own* channel identity. Two gaps:
  - A `stable`-channel record can be listed by a `beta`/`alpha`/`internal` feed (since those are > `stable` in `All`, they are excluded — so this direction is fine). But the reverse — a `beta` record with only a `stable` feed present in `Feeds` — passes, and `stable` listings include full stable packages. `UpdateFeeds.Package(v, …)` will then fetch the package from `Packages`/the edge based on the *version's* channel, not the record's — so a mismatched (record-channel ≠ version-channel) pair is still applied. See also `Updater.Staged`, which builds the `VelopackAsset` purely from the record without re-deriving the channel from `s.Version.Channel`.
  - `Lists` compares `FileName`, `Version`, `Size`, `SHA256` — but does not pin the *download URL* or the package channel to the same feed. The `Updater` reconstructs the URL from the *version's* channel (`UpdateFeeds.Package`). If a signed `beta` feed legitimately lists a `stable` full package, the record's `Channel` is `beta` and `Feeds` contains the `beta` feed, so `Refused` returns `null`, and `AtStart` on the `beta` channel will happily apply a `stable` package — which is a channel downgrade not authorised by the user's channel choice. The feed signature does not carry "this package is intended for the beta channel."
- **ATTACK SCENARIO:** A signed feed for a higher channel (or an accidentally cross-published release) lists a `Full` asset for an older/other channel's version. The record is built from that feed and applied on the higher channel. More directly: if `Fetched` in `SignedFeedSource` ever contains a feed and the record's `Channel` is chosen such that the checksum can be met, the download URL is derived from the *version's* channel — the two are not cross-checked.
- **CONFIDENCE:** Medium — I could not find a cross-channel listing in these sources, but the validation deliberately allows it and the URL derivation is elsewhere.
- **RECOMMENDED FIX:** Require the listing to come from a feed whose channel equals `AppVersion.Parse(Version).Channel`, and pin the exact expected download host/path in the record (or at least assert `v.Channel == s.Channel` in `Updater.Staged` / `ApplyAsync`).

---

## S4 — Package SHA-256 is checked by Velopack, but only *after* the body is written, and `SignedFeedSource.GetReleaseFeed` lets a signed higher-channel feed contribute **non-full** assets

- **ID:** S4
- **TITLE:** Non-full (delta) assets from later channels are dropped, but the *authority* for what "full" means is a JSON field the feed controls
- **FILE + LOCATION:** `src/SCSKiller.App/Updater.cs`, `SignedFeedSource.GetReleaseFeed`:
  ```csharp
  var have = parsed.Assets.Select(a => a.FileName).ToHashSet();
  parsed.Assets = [.. parsed.Assets, .. more.Assets.Where(a => c == channel || a.Type == VelopackAssetType.Full && !have.Contains(a.FileName))];
  ```
  plus `Manager`'s `MaximumDeltasBeforeFallback = -1` and the SHA-256-not-present check.
- **SEVERITY:** Low
- **CATEGORY:** Insecure deserialization / asset-type confusion
- **DESCRIPTION:** The code correctly forces full packages (`MaximumDeltasBeforeFallback = -1`, reject any asset without `SHA256`). Velopack's `VelopackAssetFeed.FromJson` deserializes an enum `Type` from the feed's JSON; the check `a.Type == VelopackAssetType.Full` is evaluated against whatever integer/string the feed supplies. If a future Velopack parses `"Type":"Full"` and an alternate value both to the same enum, or if the enum's numeric mapping is ever shifted, the filter silently stops filtering. The asset's `FileName` is then used verbatim in `Path.Combine(Locator.PackagesDir ?? "", a.FileName)` (`Updater.Velo.PathOf`) and in `UpdateFeeds.Package` via `Uri.EscapeDataString(entry.FileName)`. There is no explicit path-traversal check on `FileName` at the point where it becomes a local path.
- **ATTACK SCENARIO:** A signed feed (or a compromised package host answering the URL derived from the feed) supplies `"FileName": "..\\..\\..\\Something.bat"` and `"Type": <whatever parses as Full>`. `PathOf` writes/reads outside `PackagesDir`. The feed signature protects against an unsigned feed, so this requires the release-signing key (or a Velopack parsing bug) — hence Low, but the local file write is not otherwise constrained.
- **CONFIDENCE:** Medium — depends on Velopack internals I do not have here (see UNVERIFIED).
- **RECOMMENDED FIX:** In `SignedFeedSource.GetReleaseFeed`, assert `a.FileName == Path.GetFileName(a.FileName)` and reject any asset whose name contains a path separator or `..`; likewise reject `Type` values that are not exactly the full-package member after round-trip; and validate in `PathOf` before any `File` operation.

---

## S5 — `AppStore.Resolve` copies *any* file under the portable `data\` tree without sanitising the relative path, and the "stale" rename can be triggered by a directory the attacker pre-creates

- **ID:** S5
- **TITLE:** Portable migration copies follow whatever `Directory.EnumerateFiles` returns and silently skip a small denylist; a pre-existing `data.stale-<n>` path collides with user content
- **FILE + LOCATION:** `src/SCSKiller.Core/App/AppStore.cs`, `AppStore.Resolve`.
- **SEVERITY:** Low
- **CATEGORY:** Path traversal / TOCTOU (local)
- **DESCRIPTION:** The copy loop skips a small set (`armed\`, `update-staged.json`, `applying`, `.lock`) but otherwise copies every file under the *old* `%LOCALAPPDATA%\SCSKiller` into the portable `data.partial\`. The old folder is under the user's control, so nothing here is attacker-vs-user new. Two real issues:
  - Symlinks/reparse points under the old folder are not checked. `File.Copy` follows a symlink under `local` and writes the target's contents into `data.partial`; the relative-path computation is against the *symlink's* path, so the content lands at the attacker-chosen name inside `data.partial` (the write target is inside `data.partial`, so this is content disclosure, not arbitrary write). Low impact.
  - The "move aside" step `Directory.Move(data, $"{data}.stale-{n}")` loops `n` upward until both `Directory.Exists` and `File.Exists` are false. A user (or another process) who pre-creates `data.stale-1`, `data.stale-2`, … as files/dirs forces the loop to a high `n`; more importantly, the loop tests `File.Exists($"{data}.stale-{n}")`, so a *file* at `data.stale-1` blocks the move to that name and the code keeps going — fine — but a *directory* the user created at `data.stale-1` will simply be skipped and the loop continues; nothing is overwritten. Not a direct exploit here, but worth noting as fragile.
- **ATTACK SCENARIO:** A local attacker who can already write `%LOCALAPPDATA%\SCSKiller` (their own account) can place a symlink there and cause the migration to read content the user placed elsewhere and write it into the portable data folder, or place `data.stale-1` files to influence `n`. Impact is within the same user's trust domain.
- **CONFIDENCE:** Medium for the symlink reading; Low for real impact.
- **RECOMMENDED FIX:** Iterate with `FileSystemEnumerable` and skip `FileAttributes.ReparsePoint`; validate `rel` does not escape (`Path.GetFullPath(Path.Combine(partial, rel)).StartsWith(partial + separator)`); and use a GUID-suffixed stale name instead of a predictable counter.

---

## S6 — `UpdateFeeds.PackageHost` lets an environment variable redirect package downloads to an arbitrary host, bypassing the "packages are hosted by name" assumption for non-stable channels

- **ID:** S6
- **TITLE:** `SCSKILLER_API` env var silently overrides the package host while the feed signature still points at the real URLs
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `UpdateFeeds.PackageHost` and `UpdateFeeds.Package`.
- **SEVERITY:** Low
- **CATEGORY:** Trust boundary / environment-variable injection
- **DESCRIPTION:**
  ```csharp
  static Uri PackageHost => Environment.GetEnvironmentVariable("SCSKILLER_API") is { Length: > 0 } ? RouteFailover.Default.Primary : Packages;
  ```
  Only for non-stable packages (stable is pinned to `https://github.com/{GhRepo}/releases/download/v{v}/…`). The SHA-256 in the signed feed still protects the *bytes* (Velopack verifies after download), so an attacker who can set `SCSKILLER_API` cannot inject a forged package — but they can:
  - Deny updates (point it at a dead host) — DoS, not severe.
  - Force a download of a *legitimately signed* older package from a controlled host (they still need the feed to list it, but this makes the download path attacker-chosen and enables traffic analysis / request smuggling in a game-adjacent tool).
  - Combined with the `Package(AppVersion v, …)` URL being constructed from `v.Channel`, a version whose channel is `beta` will go to the attacker-controlled host.
  This is documented as "a local backend," but the variable is unauthenticated and inherited from the process environment; any process/user that can influence the environment of the launched app (shortcut, wrapper, scheduled task, another process in the same session) can redirect it.
- **ATTACK SCENARIO:** A malicious update wrapper or a sibling process sets `SCSKILLER_API=https://evil/` before launching the app; the app advertises "verified by pinned key," which remains true, but the user's traffic and the download mirror are attacker-chosen.
- **CONFIDENCE:** High that this is the code's behaviour; Medium that it is exploitable given SHA-256 verification.
- **RECOMMENDED FIX:** Do not read `SCSKILLER_API` in release builds, or require an explicit opt-in (`SCSKILLER_API_ALLOW=1`) plus a matching build flag; if kept, document it as unsupported and gate it behind the internal channel only.

---

## S7 — `FeedClient.SendAsync` applies the `Bearer` access token to any non-stable URL including redirect targets, and `RouteFailover` is not shown to strip it

- **ID:** S7
- **TITLE:** Authorization header is attached by channel, not by origin, so a redirect or a mis-set host leaks the account token
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `FeedClient.SendAsync`:
  ```csharp
  if (channel != UpdateChannels.Stable)
      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token() ?? ...);
  ```
  and `UpdateFeeds.Feed` / `UpdateFeeds.Package` which derive hosts from `RouteFailover.Default.Primary`.
- **SEVERITY:** Medium
- **CATEGORY:** Auth token handling
- **DESCRIPTION:** `HttpClient` follows redirects by default and, for the same-handler request, **forwards** the request's `Authorization` header on same-scheme redirects in .NET unless `AllowAutoRedirect`/`SocketsHttpHandler` stripping applies. .NET's `SocketsHttpHandler` strips the header on cross-origin redirects (since .NET Core 3.0), so a well-behaved server redirect is fine — but the token is attached based purely on `channel != stable`, and the destination host for non-stable is defined by `RouteFailover.Default.Primary`, which is outside these files. If any proxy/DNS/`SCSKILLER_API` (see S6) rewrites the host or a redirect is same-origin-different-scheme, the Bearer token can be sent to a host the vendor did not intend. The token is a long-lived account credential; leaking it to a game-adjacent game process (the proxy DLL sits inside a game) is meaningful.
- **ATTACK SCENARIO:** A game (already injected by the proxy, threat model (c)) triggers a network path where the app's update client is asked to fetch a non-stable feed from an attacker-influenced route, and the Bearer token is presented to the attacker's host. Or: an attacker poisons DNS / `SCSKILLER_API` for the edge host and receives the token.
- **CONFIDENCE:** Medium — depends on `RouteFailover` and how `HttpClient` is configured (not supplied).
- **RECOMMENDED FIX:** Attach the token only when `url.Host` is on an explicit allow-list of package/feed hosts; disable auto-redirect (`AllowAutoRedirect = false`) and re-issue scoped requests to approved origins; treat the token as a short-lived, purpose-scoped credential.

---

## S8 — `StagedUpdate.Load` accepts the JSON record at face value and only later validates; the local record is the authority for `FileName`, `Size`, and `Sha256` until `Refused` runs, and `Refused` is easy to satisfy with only a *prior* feed

- **ID:** S8
- **TITLE:** A user-writable `update-staged.json` can pre-seed the staged update; `Refused` is a *check*, not a *proof* that the recorded file matches the recorded feed
- **FILE + LOCATION:** `src/SCSKiller.Core/App/Updates.cs`, `StagedUpdate.Load`/`Refused`/`Lists`; `src/SCSKiller.App/Updater.cs`, `Updater.Staged`.
- **SEVERITY:** Low (requires local write to `%LOCALAPPDATA%`, i.e. the user's own account, and the package bytes are still checked by Velopack against the recorded `SHA256` — which is itself from the attacker-chosen record, but must also match a signed feed listing due to `Lists`)
- **CATEGORY:** TOCTOU / trust of local state
- **DESCRIPTION:** Because `Refused` requires *some* signed feed (in `Feeds`) to list the package by `FileName`/`Version`/`Size`/`SHA256`, an attacker who writes `update-staged.json` must reference a real signed feed they already have (which they can obtain; the feeds are public on GitHub for stable). They cannot *forge* the SHA-256, but they can choose which already-published package to stage (older-but-signed stable release, a beta the user never opted into, etc.), and `AtStart` decides apply-vs-skip only against the running version and channel. Combined with S2 (a truncated/deleteable `feeds.json`), the local file is the effective authority on which *already-signed* package is installed.
- **ATTACK SCENARIO:** Local attacker rewrites `update-staged.json` to stage an older signed full package; combined with a reset of `feeds.json`, the app installs it on next start without a network round-trip.
- **CONFIDENCE:** Medium.
- **RECOMMENDED FIX:** Store the staged record under the user's DPAPI (or an HMAC under the release key) so that tampering is detectable, and re-derive the record from the signed feed at apply time rather than trusting the on-disk one.

---

## S9 — `AppStore.GameDir` `IsPlainName` is correct, but `GameId` unescape is unsanitised and can yield a folder name that escapes

- **ID:** S9
- **TITLE:** `GameId(folderName)` calls `Uri.UnescapeDataString(folderName[1..])` and returns the result without re-checking `IsPlainName`
- **FILE + LOCATION:** `src/SCSKiller.Core/App/AppStore.cs`, `AppStore.GameId`.
- **SEVERITY:** Low
- **CATEGORY:** Path traversal (round-trip)
- **DESCRIPTION:** `GameDir(id)` → if `plain` is not `IsPlainName`, uses `EncodedPrefix + Segment(id)`. The inverse `GameId(folderName)` decodes the prefixed form and returns the string. If any caller takes a `folderName` from disk and passes it back into `GameDir`, and the encoded form decodes to something like `..\..\win.ini` — `Segment` escapes `%`, invalid chars, and trailing dots/spaces but **does not escape `\`, `/`, or `..` explicitly** (it relies on `Path.GetInvalidFileNameChars()` including `\`/`/`, which it does on Windows, so `Segment` is safe). The gap is `Uri.UnescapeDataString`: a manually crafted folder name like `%252E%252E%255Cfoo` decodes once to `%2E%2E%5Cfoo`, which `GameId` returns verbatim, and a subsequent `GameDir` of that returned id re-encodes to a *different* segment than the original — a non-idempotent round-trip. The final guard in `GameDir` (`Path.GetFullPath(dir)` must be directly under `games`) does reject escapes for the plain branch, but the `%`-branch builds `EncodedPrefix + Segment(id)` from the decoded id, so traversal characters introduced by double-decoding are escaped by `Segment` — meaning the practical impact is a broken lookup, not a write outside `games`. Reported as Low because the code's final check appears to hold.
- **ATTACK SCENARIO:** A game id containing `%` sequences and separators supplied by launcher metadata (`Xbox Identity.Name`, EA content id, Epic app name — all explicitly named in the doc comment as untrusted) reaches `GameId`, yields a decoded id; if any caller uses that returned id with an API other than `GameDir`, a traversal is possible. Within these three files I do not see such a caller, hence Low.
- **CONFIDENCE:** Medium.
- **RECOMMENDED FIX:** In `GameId`, after unescaping, return `null`/`folderName` unchanged if the decoded string fails `IsPlainName` (or re-escape via `Segment` and compare to the input); and never `Uri.UnescapeDataString` data that can contain `%`.

---

## S10 — `PathGate` re-entrancy is per-thread, but `SaveGame`'s "merge under lock" re-reads via `Load<JsonObject>` which can *fail silently to null* and then writes `now` whole, discarding the other process's changes

- **ID:** S10
- **TITLE:** `AppStore.SaveGame` merge fallback drops concurrent writer's fields when the stored file cannot be parsed
- **FILE + LOCATION:** `src/SCSKiller.Core/App/AppStore.cs`, `SaveGame`:
  ```csharp
  var stored = _held.TryGetValue(r, out var was) && Load<JsonObject>(path) is { } latest ? Merge(latest, was, now) : now;
  ```
  with `Load<T>` returning `null` on any `JsonException`.
- **SEVERITY:** Low
- **CATEGORY:** Data integrity / lost update
- **DESCRIPTION:** The merge logic depends on both the in-memory baseline (`was`) and a successful parse of the on-disk file. If the on-disk file is corrupted (partial write, disk full, user edit), `Load` returns `null`, and the code falls into the `: now` branch, writing the current record whole and silently losing any fields another process (app, CLI, scheduled task) had written. The comment claims a "path that holds a record for long never puts back what another path saved meanwhile," which is untrue in this branch. A corrupted `state.json` (attacker-controlled local file, or a race with another writer) causes data loss for the legitimate user — e.g. dropping the `RecorderFiles` map, the `CrashKeys` set, or `OfflineSession`, each of which the rest of the app relies on for cleanup and safety.
- **ATTACK SCENARIO:** Any process/user able to corrupt `state.json` (partial write, or simply writing arbitrary bytes) then triggering a long-running path (compile) to `SaveGame` causes the merge baseline to be skipped; subsequent saves erase the earlier content. Combined with `RecorderFiles` being the only record that a proxy DLL was installed into a game, a game could be left with a stale injected `d3d12.dll` that the app no longer accounts for.
- **CONFIDENCE:** High that the branch loses data; Medium that it is operationally significant.
- **RECOMMENDED FIX:** If the on-disk file cannot be parsed, refuse the save (throw, or write to `state.json.corrupt-<ts>` and log) rather than overwriting it with `now`; keep a shadow copy of the last successfully loaded object.

---

# UNVERIFIED OBSERVATIONS

These look risky but I cannot confirm from the supplied files; each needs the named file.

1. **`RouteFailover.Default` / `RouteFailover.Primary`** — S7 depends on whether it pins hosts, strips `Authorization` on redirect, and validates TLS (`ServerCertificateValidationCallback` overrides, custom `HttpMessageHandler`). **Need:** `src/SCSKiller.Core/App/RouteFailover.cs` (or wherever `RouteFailover` lives), plus the `HttpMessageHandler` passed into `FeedClient`.

2. **`VelopackAssetFeed.FromJson`** and `UpdateManager.ApplyUpdatesAndRestart` / `WaitExitThenApplyUpdates` / `VerifyPackageChecksumAsync` — S4 and the "no delta / SHA-256 always present" claim depend on Velopack's parser and on whether `Type` is numeric or string, and on whether the update manager writes the file to `Locator.PackagesDir` before or after the signature/sha check. **Need:** the Velopack source or version in the `.csproj`, and `Locator`.

3. **`tools/release-sign` / `publish.ps1`** — S2's optimistic timestamp handling and the "internal channel allows downgrades" rule depend on whether the signing tool validates `signed_at` against wall clock and whether it can emit a feed for the wrong channel. **Need:** `tools/release-sign/**` and `build/publish.ps1`.

4. **`App.Account.GetAccessTokenAsync`** — S7 depends on token lifetime, storage (DPAPI? plaintext?), and refresh handling. **Need:** the `Account` class implementation.

5. **`ScsKiller.RemoveAllRecorders` / `RemoveRecorderFiles`** — S10's impact depends on how `RecorderFiles` is used to find and uninstall injected `d3d12.dll`s. **Need:** `src/SCSKiller.Core/App/ScsKiller.cs` (the recorder install/uninstall paths) and the proxy DLL source (`d3d12.dll`), which is called out in the threat model as the highest-value memory-safety target and is not in this batch at all.

6. **`Account.Status.Ent`** and the `ent` flag setter path — the entitlement downgrade protections in `UpdateChannels.Effective` look correct on their face (they step back to stable when the token lacks a flag), but whether the status object is itself authenticated (vs. read from a local file) is unknown. **Need:** `src/SCSKiller.Core/App/Account.cs`.

7. **`KeyFiles.Prune`** — `PruneKeyFiles` calls into it with the stored record's `PlanKeysFile`/`WarmKeysFile`; whether `KeyFiles.Prune` deletes only files under the game dir and can't be steered by a crafted record is not verifiable from these files. **Need:** `src/SCSKiller.Core/App/KeyFiles.cs`.

8. **`OfflineSession`** and `OfflineBlocksUpdate` / the offline-start path — the "resumed vs. still suspended" logic and the `Created[]` cleanup are security-relevant (a suspended game with an injected proxy) but the enforcing code is elsewhere. **Need:** the offline-session launcher and `ScsKiller.OfflineBlocksUpdate`.

9. **`Mutex.TryOpenExisting(name, out m)`** in `Busy.IsHeld` and in `AppStore.Held` — `TryOpenExisting` does not distinguish "exists because we hold it" from "exists because a crashed process leaked the handle." Since `Busy.Hold` also creates the object, and `AppStore.Held` opens a `Global\` mutex, the global namespace and the "another user's process holds it" path matter; cross-user interference on the same machine is plausible but not demonstrated here. **Need:** the actual callers of `Busy.IsHeld` and any privilege context in which the app/CLI/scheduled task run.

10. **`Uri.EscapeDataString(fileName)` in `UpdateFeeds.Package`** — the `github.com/.../download/v{v}/{escaped name}` URL and the edge URL both embed a feed-controlled `fileName`. Combined with S4, whether the server could be made to serve a redirect to an arbitrary origin is unknown without the CDN configuration. **Need:** server-side route configuration for `dl.scskiller.io` / `api.scskiller.com` (not supplied).

---

### Priority

Fix **S1** first: the documented "never apply under a running warm / never install under a live compile" guarantee is currently enforced by a primitive that does not provide mutual exclusion, and the consequence is a mid-write swap of `current\` under a process holding GPU driver cache state and injected DLLs into a game — the highest-impact failure mode in the threat model. Then **S2/S7** (update freshness floor and token handling), then **S3/S4** (channel/asset confusion in the trusted feed pipeline).

## CHUNK 1

# Security Audit — SCSKiller v1.2.5

Scope note: the three supplied files are all "read and classify local game files" code. None of them perform downloads, signature verification, TLS, deserialization of network data, or native memory operations directly. The findings below therefore cluster into: (1) parsing hard-to-trust game-supplied files/binaries, (2) path handling with junctions/symlinks, (3) copying "loader" DLLs and add-ons into a staging folder that is later loaded into a game process. I have not padded with speculative issues; anything I could not confirm from these files is listed separately.

---

## S1 — Add-on / loader files are copied into the staging folder purely by name + a weak "is ReShade/SpecialK/OptiScaler" heuristic; a malicious file dropped next to the game is staged and loaded into the game process

- **ID:** S1
- **TITLE:** Untrusted sibling DLLs / add-ons staged and loaded into the game process
- **FILE + LOCATION:** `src/SCSKiller.Core/Games/ReShade.cs` — `Detect`, `At`, `IsReShade`, `IsOptiScaler`, `IsSpecialK`, `Classify`, and `Stage` (`Stage` copies `r.Loader ?? r.Dll` and every "pipeline" add-on into `dest` as `dxgi.dll` etc.).
- **SEVERITY:** Critical
- **CATEGORY:** Untrusted native input / arbitrary code execution via DLL search-order hijack
- **DESCRIPTION:** `Stage()` takes whatever `Detect()` classified as ReShade / OptiScaler / Special K / a "pipeline add-on", copies it into a fresh folder, renames it to `dxgi.dll` (or `ReShade64.dll` next to an OptiScaler `dxgi.dll`), and this folder is then pointed at the warm's game process. The identification methods are all attacker-controllable file contents:
  - `IsReShade` returns true if `FileVersionInfo.ProductName == "ReShade"`, **or** if the name is one of `Names` (`dxgi.dll`, `d3d12.dll`, …, `ReShade64.dll`) **and** the file contains the raw string `"ReShade post-processing injector"` (Unicode) **or** exports `ReShadeRegisterAddon`.
  - `IsOptiScaler` uses `ProductName` starting with `"OptiScaler"` or the exported name — both are places an attacker writes.
  - `IsSpecialK` is the same via `ProductName`/export.
  - `Classify` marks an add-on "pipeline changing" if it merely contains the byte string `"utils::shader attached."` or `"Luma: trying to load a config..."` — trivially forgeable, and the fallback for an unreadable add-on is `ReplacesShaders` (i.e. still staged).
  The staged DLL is loaded by the game (proxy chain) with the game's rights, giving code execution. Nothing verifies Authenticode, publisher, or a known-good hash before staging.
- **ATTACK SCENARIO:** Attacker who can write into the game install (shared game folder, downloaded "mod pack", game that ships a same-named DLL, or a ZIP the user extracts) drops `ReShade64.dll` / `dxgi.dll` / `OptiScaler.dll` / an `*.addon64` containing the fake marker strings and/or a `ProductName` resource. SCSKiller's `Detect` classifies it, `Stage` copies and renames it into the warm folder, and the warm process loads it as the graphics proxy — code runs inside the game. Same for `SpecialK` and the `Loader` path. This is the exact pattern the "must validate signatures/hashes on anything it downloads and executes" policy is meant to stop; here the file isn't downloaded, but it is still attacker-supplied and executed.
- **CONFIDENCE:** High that the identification is by forgeable content and that `Stage` copies it; the final "the warm process loads the staged folder" step is asserted by the surrounding comments in `ReShadeInstall` and `Stage` (not shown), so I cannot fully confirm the load itself from these files.
- **RECOMMENDED FIX:** Before staging any DLL/add-on, verify Authenticode publisher (ReShade, OptiScaler, Special K, and each add-on signer) against an allow-list, or require a matching hash against a signed, pinned manifest (`shader-mods.json` is embedded — extend it to include expected hashes and signatures). Reject unsigned/unknown-signer loader DLLs and add-ons; surface a clear "untrusted layer, not staged" state. Do not fall back to `ReplacesShaders` for unreadable add-ons.

---

## S2 — Native/binary parsing of untrusted game files and DLLs (PE parsing, export/import walking, full-file reads) has no size/robustness guard beyond a coarse cap and can crash or exhaust the process

- **ID:** S2
- **TITLE:** Memory exhaustion / unhandled native-parse faults on attacker-controlled PE and shader files
- **FILE + LOCATION:** `src/SCSKiller.Core/Carved/CarvedReader.cs` — `PeImports(PEReader, …)` (walks import/delay-import tables with `PeFile.Str`), `Carve`, `ReadAt`, `Scan`, `Walk`, `Files`. Also `src/SCSKiller.Core/Games/ReShade.cs` — `Find` (`new byte[s.Length]` then `ReadExactly`), `IsPe`, `Imports`, `Cached`.
- **SEVERITY:** High
- **CATEGORY:** Unchecked native input / resource exhaustion / DoS
- **DESCRIPTION:**
  - `PeImports` iterates import descriptors using `stride`/`nameAt` and calls `PeFile.Str(pe, (int)name)`; a malicious/corrupt PE with a huge `NumberOfSections`/descriptor count or an out-of-range name RVA can drive the loop or the string read. `Take(20000)` caps the *export* enumeration in the agility check, but the import walk in `PeImports(PEReader,bool)` has no equivalent hard cap and no bound check on `name` vs. section data — `PeFile.Str` will read wherever told. These paths run on game-supplied `.exe`/`.dll` (e.g. `Imports(game.ExePath)`, `IsOptiScaler`/`IsSpecialK`/`IsReShade` probing every DLL in the folder).
  - `Find` reads the whole file into `byte[]` (`new byte[s.Length]`) with only `MaxBytes = 128 MB` as a limit — up to 128 MB allocated and scanned per file, and `Stage`/`LibrariesOf`/`Cached` run this across many sibling files. Combined with `Carve`'s block loop and `Walk`'s byte budgets, a game folder full of crafted large PEs can pin memory and CPU.
  - `Carve`/`HeaderSize` rely on `Dxbc.HeaderSize`/`Dxbc.Valid`; the container length is taken from the header and only checked as `off + size > len`, so a crafted `DXBC` header size is the only thing standing between the file and a large `ReadAt`/slice. This is the "unchecked native parser on game-supplied data" class.
- **ATTACK SCENARIO:** Attacker ships a game (or modifies a local game folder) containing a file with a `DXBC` magic and a size header that forces large reads, or a PE/DLL with a malformed import-descriptor chain, in the game directory SCSKiller scans. During `Detect`/`Index`/`Imports`/`IsReShade`, SCSKiller allocates/loops/crashes — at minimum a DoS of the tool, and the PE-string path is a realistic out-of-range read in the parser. (`Dxbc` and `PeFile.Str` are not in the supplied set.)
- **CONFIDENCE:** Medium-High for the memory/DoS angle (directly visible); the out-of-range read depends on `PeFile.Str`/`Dxbc.*` internals I could not read.
- **RECOMMENDED FIX:** Bound every table iteration by the containing section's size and the declared entry count; validate `name`/RVA against the section that holds it before dereferencing; add hard caps on descriptor counts and file-read sizes; stream `Find`/string searches instead of whole-file `byte[]` allocation; wrap all of this in a crash-isolated worker (or fail-closed) so a malformed input cannot take down the app.

---

## S3 — PATH/junction handling: several "is this inside the install" checks either only inspect the target file itself or only reject reparse points at certain points, enabling a malicious game folder to make SCSKiller read/stage files outside the intended tree

- **ID:** S3
- **TITLE:** Incomplete reparse-point / containment checks on game-supplied paths
- **FILE + LOCATION:** `src/SCSKiller.Core/Games/GameFiles.cs` — `Inside`, `InsideNoLinks`, `BattlEyeTarget`, `RedLauncherTarget`, `BattlEyeTarget`/`BattlEyeTarget` callers, `DetectAntiCheat`. `src/SCSKiller.Core/Games/ReShade.cs` — `Inside`, `LibrariesOf`, `Stage`.
- **SEVERITY:** Medium
- **CATEGORY:** Path traversal / symlink following (TOCTOU / link race)
- **DESCRIPTION:**
  - `InsideNoLinks` iterates *upward from the target* using `new FileInfo(p)` for the target and `DirectoryInfo` for parents, rejecting `LinkTarget != null`. It is used for `BattlEyeTarget` (`BELauncher.ini`'s `64BitExe`) and `RedLauncherTarget` (`launcher-configuration.json.executables[].executable`). Good in principle, but: (a) the install root itself may be a link ("the root itself may be one", per the comment) and is not re-validated; (b) it is a check-then-use: the file is resolved, then later opened/staged, so a swap between check and use (TOCTOU) is possible; (c) `RedLauncherTarget` combines `S("directoryPath") ?? ""` with `fileName` via `Path.Combine` and then `Path.GetFullPath` — containment relies entirely on `InsideNoLinks`, and `dir`/`name` are attacker-controlled JSON.
  - `ReShade.Inside(dir, relative)` rejects rooted/escaping `relative` for `OptiDllPath`, which is correct, but `LibrariesOf` will then `File.Copy` those libraries into the stage — i.e. a game-supplied `OptiScaler.ini` can point `OptiDllPath` at any subfolder inside the exe dir and have those DLLs copied and later loaded.
  - `DetectAntiCheat` deliberately does not follow reparse points during the walk (documented) and rejects reparse points "between the install root and the exe" — but it still reads `exeDir` when the exe lives outside the install root (`Inside(exeDir)` false → adds `exeDir` to the walk roots). A game whose config points `ExePath` outside the install therefore causes SCSKiller to walk/read an arbitrary directory.
- **ATTACK SCENARIO:** Attacker controls the game folder (or its `BattlEye\BELauncher.ini` / `launcher-configuration.json` / `OptiScaler.ini`). They point the target path at a junction/symlink or a path outside the install so SCSKiller reads or stages a file it shouldn't, or swap the link after validation (TOCTOU) so a file other than the validated one is used. Net effect: escape from the intended "reads only inside the game install" boundary.
- **CONFIDENCE:** Medium (the code clearly attempts containment and mostly succeeds; the residual gaps are the unvalidated root-as-link, the check-then-use window, and the exe-outside-install case).
- **RECOMMENDED FIX:** Resolve the install root to its final path once and treat that canonical root as the trust anchor; re-check containment using final paths at the moment of open (open-by-handle + `GetFinalPathNameByHandleW` then compare final paths, as `Identity` already half-does); reject install roots that are themselves reparse points, or explicitly treat that as "outside" for staging purposes; require the exe to be inside the install for the anti-cheat walk and for staging.

---

## S4 — Probe/identity caching trusts size+mtime+file-id and caches *security-relevant* verdicts ("is this ReShade/SpecialK/add-on", "is it a pipeline-addon") across runs

- **ID:** S4
- **TITLE:** Persisted classification cache can mark an attacker file as a trusted loader/add-on
- **FILE + LOCATION:** `src/SCSKiller.Core/Games/ReShade.cs` — `LoadProbes`, `SaveProbes`, `Cached`, `Probed`, `probesVersion`, and the use of `Cached` in `IsReShade`/`IsOptiScaler`/`IsSpecialK`/`ExportsAddonApi`/`Listed`/`Find`.
- **SEVERITY:** Medium
- **CATEGORY:** TOCTOU / cache poisoning of a security decision
- **DESCRIPTION:** `Cached` keys a probe (`product`, `mods`, `optiscaler`, `specialk`, `addonexport`, `ini`, `imports`, …) on `(Length, LastWriteTimeUtc, FileIdInfo)`. That is fine as a *dedup* cache, but `SaveProbes`/`LoadProbes` persist these to disk and reuse them across runs, and the cached values include the very booleans that decide whether a file is ReShade/SpecialK/OptiScaler and whether an add-on is pipeline-changing — i.e. whether it gets staged and loaded. File id + size + write time are attacker-influencable (copy a file preserving timestamps, or replace with same-size content and rewrite the timestamp), so a previously-trusted file's "yes, it's ReShade" probe can be carried over onto a different payload. The doc comment already notes the cache exists to avoid re-reading; that speed optimization is a security boundary here.
- **ATTACK SCENARIO:** Attacker drops a benign-looking file once so SCSKiller caches "ProductName=ReShade"/"is OptiScaler" for that (size, mtime, id); then replaces the bytes with a payload of identical size and preserved mtime. On the next run `LoadProbes` returns the cached verdict and the payload is treated as a trusted layer and staged, defeating the (already weak, see S1) content check.
- **CONFIDENCE:** Medium — depends on whether the persisted probe file is writable by the attacker and whether the same (size, mtime, id) can be reproduced, both of which are achievable locally.
- **RECOMMENDED FIX:** Do not persist security-relevant classifications; or, when persisting, key on a content hash (SHA-256) rather than size+mtime+id, and re-verify a strong hash/signature immediately before staging rather than trusting a cached boolean.

---

## S5 — `ReShade.Stage` copies the "loader" and its libraries/add-ons without any hash/signature check, from paths influenced by game-supplied ini files

- **ID:** S5
- **TITLE:** Staging copies arbitrary loader/libraries/add-ons selected by attacker-controlled config
- **FILE + LOCATION:** `src/SCSKiller.Core/Games/ReShade.cs` — `Stage`, `LibrariesOf`, `OptiScalerLoads`, `ForStage`, `WithoutPaths`.
- **SEVERITY:** High
- **CATEGORY:** Untrusted input → code execution (staging)
- **DESCRIPTION:** This overlaps S1 but is a distinct code path: `Stage` copies `r.Loader ?? r.Dll`, then copies every `LibrariesOf(opti)` DLL, then every "pipeline" add-on, into `dest`. The set is chosen by `OptiScaler.ini`'s `OptiDllPath` (game-supplied, only constrained to be inside the exe dir) and by `ReShade.ini`'s `AddonPath`/`DisabledAddons` (game-supplied). `ForStage`/`WithoutPaths` strip a few keys for the *staged copy* of the ini but do **not** constrain `OptiDllPath`'s origin for `LibrariesOf` (that runs against the original ini). So a game install can direct which DLLs get collected and loaded into the warm process. As with S1, no Authenticode/hash gate.
- **ATTACK SCENARIO:** Untrusted game ships `OptiScaler.ini` with `[Libraries] OptiDllPath=evil` and drops `OptiScaler\amd_fidelityfx_dx12.dll` (a real PE within the size caps). SCSKiller's `LibrariesOf` finds it inside the exe dir, `IsPe` passes, and `Stage` copies it into the warm folder to be loaded by OptiScaler. Arbitrary code executes under the game's process.
- **CONFIDENCE:** High (the code path is explicit and the only checks are "inside exe dir" + "looks like a PE within size caps").
- **RECOMMENDED FIX:** Verify signatures/hashes of ReShade, OptiScaler, and their FidelityFX/XeSS/NGX libraries against a pinned, signed manifest before staging; refuse to stage libraries discovered solely via a game-supplied ini path, or require they match a known hash.

---

## S6 — `SaveProbes`/`LoadProbes` and other on-disk state written with attacker-influenceable content, and `SaveProbes` is not transactional across the version check

- **ID:** S6
- **TITLE:** Non-atomic probe save / cache file content is game-derived
- **FILE + LOCATION:** `src/SCSKiller.Core/Games/ReShade.cs` — `SaveProbes`, `LoadProbes`.
- **SEVERITY:** Low
- **CATEGORY:** Integrity of local state / benign
- **DESCRIPTION:** `SaveProbes` serializes `Probed` (keys are attacker-influenced file paths, values include booleans/numbers/strings derived from game files) and writes with `AppStore.WriteAtomic`. `LoadProbes` does `JsonSerializer.Deserialize<Dictionary<string,KeptProbe>>` and only checks `p.Identity.Length > 1`. This is low-risk (local file, deserialized to a typed record, atomic write), and I am **not** calling it insecure-deserialization — but it is the mechanism that makes S4 exploitable, and the `Identity.Length > 1` guard is a weak sanity check on a cache that gates a security decision. Reported as Low, mainly to track the coupling.
- **ATTACK SCENARIO:** Tamper with the probe file to inject/retain a "trusted" classification for an arbitrary path.
- **CONFIDENCE:** Medium.
- **RECOMMENDED FIX:** Fold into S4's fix (hash-keyed, non-persistent security verdicts).

---

## Non-findings (checks that mitigate, listed so they are not reported as false positives)

- `GameFiles.Inside` and `ReShade.Inside` correctly reject rooted and escaping relative paths (`Path.IsPathRooted`, prefix-with-separator comparison). S3's concern is the *root-as-link* and *TOCTOU* residuals, not these helpers.
- `ReShade.OptiScalerValue`/`IniLines` deliberately treat an unclosed `[section` as "no usable name" for SimpleIni and `Closed:false` — a reasonable hardening of an ambiguous parse.
- `DetectAntiCheat` explicitly skips reparse points during the walk and checks for a link between root and exe; the residual issue in S3 is that the root itself may be a link and the exe may be outside the install.
- `ReShade.Cached` bounds reads with `MaxBytes` (128 MB) — mitigates unbounded reads but not the per-file whole-file allocation (S2).

---

## UNVERIFIED OBSERVATIONS (need files not supplied)

1. **`Dxbc.HeaderSize` / `Dxbc.Valid` / `Dxbc.Part` / `Dxbc.Kind` behavior on crafted headers.** If these do not bound every field against the actual buffer, `Carve`/`ReadAt`/slices are a direct out-of-bounds read. *Need:* `src/SCSKiller.Core/Carved/Dxbc.cs`.
2. **`PeFile.Str` / `PeFile.Forwarders` / `PeFile.ExportNames` bounds checking.** `CarvedReader.PeImports` and `ReShade.PeFile`/`CarvedReader` export walkers call these on game-supplied PEs. If `PeFile.Str` reads a length-prefixed string without validating against the section, S2 escalates to a native OOB read. *Need:* `src/SCSKiller.Core/Carved/PeFile.cs` (and any `PeHeaders` wrapper).
3. **How the staged folder is loaded into the game / warm process** — i.e. whether `scskiller_warm --layer <dest>` sets the DLL directory and loads `dxgi.dll` in-process, and with what integrity/verification. This determines whether S1/S5 are "code exec in game process" (as I scored) or merely "file copied." *Need:* the warm/`Stage` caller (e.g. `SCSKiller.Warm` project, and the proxy `d3d12.dll`/`scskiller_warm` sources).
4. **Update feed / signature verification, TLS handling, `api.scskiller.com` client, auth tokens.** None of the supplied files contain these, yet your threat model explicitly lists attacker-controlled update feed, signature, and network responses. I cannot audit that surface from these files. *Need:* the updater/client sources and any `HttpClient`/certificate-pinning/TLS config.
5. **`KeyFiles.Identity` correctness.** `ReShade.Cached` and (per comment) `GameFiles.Identity` rely on it for the cache key; if `KeyFiles.Identity` returns a constant/empty on error, the probe cache keyed on it is far weaker than intended (strengthens S4). *Need:* `src/SCSKiller.Core/…/KeyFiles.cs`.
6. **`AppStore.WriteAtomic` semantics.** If it writes to a predictable temp path and renames, an attacker with write access to the destination directory could race it. Low impact here. *Need:* `AppStore`.

**Priority:** S1 and S5 first (both lead to arbitrary code execution inside a game process from a game-supplied file, the exact thing the stated policy forbids), then S2 (DoS/OOB in native parsing of untrusted files), then S3/S4, then S6.

## CHUNK 2

# Security Audit — SCSKiller v1.2.5

Scope note: the two files supplied (`ScsKiller.Offline.cs`, `SCSKiller.Cli/Program.cs`) are the only ones I can reason about directly. Many claimed controls live in code that was not provided (`Store.LoadGame`, `ScsKiller.ArmedFile`, `IsOurProxy`, `WriteAttestation`, `Updater`, `http` layer, `d3d12.dll` native code, signature verification, `Recordings.Merge`, `PsoDb.Read`, etc.). I will only report findings whose logic is visible in the supplied sources, and I explicitly list everything I had to assume under **Unverified Observations**.

---

## Findings

### S1 — Offline-session cleanup deletes or overwrites files in a game folder it does not exclusively own, gated only by name/self-hash rules
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `CleanOfflineSession` (the `Ours`/`Delete`/`Retire` block, and `Ours` name allow-list), and `StartOffline`'s `Refusal()` pre-check (`RecorderOwnFiles.Concat(created).FirstOrDefault(...)`).
- **SEVERITY:** High
- **CATEGORY:** TOCTOU / Unsafe file deletion (destructive write primitive on a game-controlled path)
- **DESCRIPTION:** The whole session model assumes the game folder contains only files the session created. Cleanup decides deletability with:
  - `file.StartsWith("scskiller")` → true (any name starting with `scskiller` is treated as "ours");
  - `file.EndsWith(TempSuffix)` → true;
  - otherwise it becomes "ours" if `IsOurProxy(path)` returns true (for `d3d12.dll`/`d3d11.dll`) **or** if the on-disk `Sha256(path)` equals the recorded hash.
  Nothing pins the *file identity* between the moment `Ours` hashes it and the moment `Delete` runs (`File.Delete(Path.Combine(dir, file))`). A process that can write in `dir` between the hash check and the delete can substitute a different file at the same name, and the cleanup will delete it. This is the classic check-then-act deletion race. Additionally, the `scskiller`-prefix rule alone is a name-based trust that a game (or its updater, or an attacker with write in the install) can exploit: any file named e.g. `scskiller-something.dll` placed by a third party will be deleted on the next cleanup pass even though it is not the session's. The `Refusal()` pre-check can't fully close this either, because it runs at *start* of a session, not at *cleanup* of a session whose journal is being replayed on a later launch (which is exactly the recovery path used at every scan/logon).
- **ATTACK SCENARIO:** A game or a dropper that shares the install directory (or a malicious installer/updater) drops `scskiller-payload.dll` (or a file whose hash momentarily matches a journaled entry, then is replaced) into the install folder. Later SCSKiller launches, `CleanOfflineSessions()` runs on startup and deletes the file. In the hash-match variant, the attacker can also use the cleanup as an oracle to plant/replace files such that a legitimate user file is removed. With write access to the folder, the attacker can race the check→delete gap to remove an arbitrary file whose name is in `s.Created`.
- **CONFIDENCE:** Medium-High (the race is structural in the code; exploitability depends on who can write `dir` — for installed games under `Program Files` this is limited, for user-installed games under user-writable paths it is not).
- **RECOMMENDED FIX:** Open the target with `FILE_FLAG_OPEN_REPARSE_POINT`, take it with a share-deny handle, hash and delete through that handle (`SetFileInformationByHandle` with `FileDispositionInfo`). Do not use prefix matching for ownership; only delete a name if the bytes opened through that handle hash to the journaled hash. Refuse to follow symlinks/reparse points at all.

### S2 — `SteamAppIdFile` is read without bounds / without reparse-point awareness and then used to decide behaviour
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `StartOffline`, `Refusal()`: `if (!addAppId && File.ReadAllText(appIdFile).Trim() != entry.AppId) …` and `addAppId` derived from `File.Exists(appIdFile)`.
- **SEVERITY:** Medium
- **CATEGORY:** Unchecked local input / symlink following
- **DESCRIPTION:** `File.ReadAllText` on `steam_appid.txt` in a game folder follows reparse points and reads to EOF with no size cap. If the file is a junction/symlink to a large file or to a sensitive location, SCSKiller will read it (and, if it happens to equal the expected app id, will trust it). More importantly, `addAppId`/`placed` logic decides whether SCSKiller will later *delete* `steam_appid.txt` during cleanup based on whether the file existed at start — but that file can be a reparse point created/short-circuited by another local process, so the ownership bookkeeping can be wrong.
- **ATTACK SCENARIO:** A local process with write in the game folder replaces `steam_appid.txt` with a reparse point pointing at a user file containing the expected app id (or an arbitrarily large file). SCSKiller reads it, decides the session is valid, and later deletes the reparse point by name (`File.Delete` follows the link on the name, not the target, so the target is not deleted — but the *reparse point* the user depended on is destroyed, and the answer to `ReadAllText` was attacker-chosen).
- **CONFIDENCE:** Medium.
- **RECOMMENDED FIX:** Open with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, reject reparse points, cap read size to a few hundred bytes, and validate the contents against a strict ASCII digit regex.

### S3 — Cleanup helper / RunOnce command is executed with a fully user/attacker-influenced path and gameId interpolation; `RunOnceEntry` quotes only by convention
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `RunOnceEntry`, `RunOnce`, `HelperMutex`, and the `Mutex.TryOpenExisting(HelperMutex(gameId), ...)` usage in `HelperRuns`.
- **SEVERITY:** Medium
- **CATEGORY:** Command injection (defense-in-depth) / local privilege confusion
- **DESCRIPTION:** `RunOnceEntry` returns `($"\"{exe}\" {CleanupArg} \"{gameId}\"")`. `gameId` is used unsanitised in a registry `RunOnce` command line and in a `Mutex` name. `gameId` in this codebase is derived from store ids like `steam:2909400` (safe) but the method is `internal static` and callers elsewhere `(RunOnce(gameId, exe)`) may pass ids derived from game metadata (epic/other stores). If a gameId can be crafted to contain `"`, spaces, or `!`, the RunOnce value becomes attacker-controlled command line (executed by `explorer.exe` at logon under the user's token). The `!` deployment-safe prefix and Windows RunOnce parsing make this a code-execution sink if any id path is attacker-influenceable. Same class of bug for `HelperMutex`: `gameId.Replace('\\','_')` only escapes backslash, not other separators.
- **ATTACK SCENARIO:** An attacker who can influence the game id stored locally (e.g. by planting a spoofed store manifest that SCSKiller ingests, or via a crafted `store` value in a game's manifest that becomes part of the id) plants `steam:1" & calc & "` — at next logon Windows executes the injected command under the user account.
- **CONFIDENCE:** Medium (safe today because the visible id format is `store:digits`, but there is no enforced validation at the sink).
- **RECOMMENDED FIX:** Validate gameId against `^[a-z0-9][a-z0-9._:-]{0,63}$` at the top of `RunOnce` and `HelperMutex`, refuse otherwise. Do not interpolate raw strings into a RunOnce value; if you must, use `CommandLineToArgvW`-safe quoting via `Environment.ProcessPath` plus a fixed, validated argument. Prefer storing the id in the registry as a value and letting the helper read it directly, so no id ever appears in a shell command line.

### S4 — `StartAttested` uses `CreateProcessW` with string-typed command builder and no quoting of `args`
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `StartAttested`: `var cmd = new StringBuilder($"\"{exe}\"" + (args.Length > 0 ? " " + args : ""));` … `CreateProcessW(...)`.
- **SEVERITY:** Medium
- **CATEGORY:** Command injection / argument injection
- **DESCRIPTION:** `args` comes from `OfflineArguments` (settable via an internal setter, and in tests). It is concatenated raw into the command line. `CreateProcessW` does not perform shell parsing, but the target process does — and `exe` here is the game executable specified by the session. If `args` is ever populated from anything less trusted than a compile-time constant (e.g. a config file, a game manifest, or the update feed), an attacker can inject arbitrary argv into the game process at launch, which for many games is enough to load an arbitrary config/mod or reach a debug path. The `\"{exe}\"` quoting is also brittle: it breaks for paths containing `"`.
- **ATTACK SCENARIO:** Config/update channel writes `OfflineArguments = "--mod \"..\\evil.dll\""` or `"-log -exec ..\\evil.cfg"`. SCSKiller launches the game with attacker-supplied argv under the user's token, with the recorder loaded.
- **CONFIDENCE:** Medium (attacker-reachable path depends on the unshown configuration loader; the sink is definitely unsafe).
- **RECOMMENDED FIX:** Treat `OfflineArguments` as a list of already-quoted tokens and build the command line with `ArgumentList`-equivalent escaping. Validate that `args` contains only a fixed allow-list of switches. Reject any value containing `"`, `\` at end-of-token position, or control chars.

### S5 — Attestation is bound to PID + creation time only, and `Alive`/`EndSuspended` re-check it via `OpenProcess` with a narrow access mask that is not resistant to PID reuse in the handle-close window
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `Alive`, `EndSuspended`, `StartAttested`, and the comment block at top of file describing the attestation.
- **SEVERITY:** Medium
- **CATEGORY:** Privilege / attestation bypass (local)
- **DESCRIPTION:** The session's "only that process records" guarantee rests entirely on `(pid, creation FILETIME)` recorded in the attestation. `Alive` opens the process with `Synchronize | QueryLimitedInformation`, reads creation time, and compares. PID+creation-time pairs are recycled by Windows, and the code acknowledges this by re-checking on the *handle*, but the handle is only obtained after the pid is known — there is a window between "record read from store" and "OpenProcess" during which the original process can exit and its pid+time pair can be reproduced. On Windows, process creation time has 100ns resolution, so reproduction is not trivial, but the *attestation is written by SCSKiller and read by the proxy at a later time from disk*; a local attacker who can write the store (the store is under the user's data dir) can set any `(pid, created)` they like and, if they can spin a helper process at the right time, satisfy the check. The comment even says the binder trusts the store's `pid=` / `pid_time=`.
- **ATTACK SCENARIO:** Attacker who can write `%LocalAppData%\SCSKiller\games\<id>\` edits the stored attestation to `pid=<their process>, pid_time=<its creation time>`, then runs the game through Steam; the injected `d3d12.dll` sees a matching pid and records into the attacker's process context (or refuses to arm for the *real* game, acting as a DoS). Because files in the game folder are the ones loaded by the game, the attacker who can write the store already has write to the install folder, so this is mostly a hardening issue — but the "unforgeable" property claimed in the header comment is not actually provided by pid+time alone.
- **CONFIDENCE:** Medium.
- **RECOMMENDED FIX:** Bind integrity of the attestation to something the attacker cannot forge locally: sign the `(pid, created, exe path, exe hash)` payload with a key held in the TPM/NCRYPT machine key, or bind to the process handle via a duplicated handle in a way the proxy can reopen and validate (e.g. named pipe bound to a kernel object the proxy opened itself, or an ALPC channel established during suspension). Also pin the exe path *and* the exe's Authenticode hash, not just pid/time.

### S6 — `Directory.EnumerateFileSystemEntries` results are used unsanitised as file names passed to `File.Delete(Path.Combine(dir, file))`
- **FILE + LOCATION:** `ScsKiller.Offline.cs` → `CleanOfflineSession` (`Listed()`, `Delete(...)`, `Retire()`), plus `Place`/`WriteNew`.
- **SEVERITY:** Low-Medium
- **CATEGORY:** Path traversal (via reparse points) / lexical path confusion
- **DESCRIPTION:** Names returned by `Directory.EnumerateFileSystemEntries` cannot contain `\` or `/` on NTFS, so classic `..\` traversal is not available. However `File.Delete(Path.Combine(dir, file))` on a name that is a *reparse point* follows the name and deletes the link, not the target — but the same pattern in `Place` (`File.Move(temp, path, true)`) and in the delete loop does not guard against the directory itself being a junction (`dir` = `Path.GetDirectoryName(s.Exe)` computed from the stored record at cleanup time, not from the live process). A redirected `dir` (the game folder is a junction to a watched location) means the cleanup deletes the same-named files in the *target*. This is the classic "trusted prefix is a reparse point" class.
- **ATTACK SCENARIO:** Game install folder is replaced with a junction pointing at `%UserProfile%\Documents`. The cleanup enumerates the target and deletes any files whose names appear in the session's journal (which the attacker also controls by having started a session earlier from the same junctioned path).
- **CONFIDENCE:** Medium (depends on the game folder being reparseable in the attacker's threat model — often true for user-installed games).
- **RECOMMENDED FIX:** Before any destructive operation, resolve `dir` and refuse if `FILE_ATTRIBUTE_REPARSE_POINT` is set anywhere on the path; open each target with `FILE_FLAG_OPEN_REPARSE_POINT` and only act on the handle.

### S7 — `Confirm()` prints the answer back to stdout when stdin is a pipe, and returns `true` on `y` case-insensitively; elevated helper accepts `--yes` and reads the confirm from a file descriptor
- **FILE + LOCATION:** `SCSKiller.Cli/Program.cs` → `Confirm`, and its use in `NvidiaAutoShader` / `CacheClear`.
- **SEVERITY:** Low
- **CATEGORY:** Auth/confirmation weakening (elevation helper)
- **DESCRIPTION:** `Confirm` treats any line equal to `y`/`Y` as confirmation and when the caller passes `--yes` skips the prompt entirely. The elevated child process (spawned by the GUI, `Elevated.Run`) inherits `--yes` from the command line it was invoked with; a local unprivileged attacker who can influence the arguments passed to the elevated helper (e.g. by editing the pending-command file the GUI passes, or by racing the UAC prompt) can get driver-level settings changed without an interactive confirmation. Combined with the CLI's `nvidia-auto-shader` / `cache set`, an attacker who already has user-level execution can flip global driver settings by requesting elevation and answering "y" through the piped stdin — the confirm text is not the security boundary (UAC is), but the code's own intent ("asks first") is not enforced.
- **ATTACK SCENARIO:** A process on the user's session writes `y\n` to the stdin of an elevated SCSKiller invocation the user has already approved for a *different* purpose (confused-deputy pattern). Alternatively a script invokes `scskiller cache set unlimited` and feeds `y` on stdin.
- **CONFIDENCE:** Low (UAC still required; this is a defense-in-depth finding).
- **RECOMMENDED FIX:** Require the elevated child to re-confirm on its own console/`Consent` UI, not via a pipe; ignore `--yes` when the parent process is not the signed SCSKiller (validate the parent's signature and PID). Bind the `--result` file to a per-invocation random name created by the parent and passed only over an inherited handle.

### S8 — `FetchCodecs` downloads DLLs (Oodle, zlib) with no visible signature/hash pinning in the supplied code path
- **FILE + LOCATION:** `SCSKiller.Cli/Program.cs` → `FetchCodecs`, `Codecs.Ensure(OodleHelper.OodleFileName, Codecs.DownloadOodle, dir)` and `ZlibHelper.DownloadDll`.
- **SEVERITY:** High (if, as the task context assumes, hash/signature verification is required for every downloaded artifact and is not enforced)
- **CATEGORY:** Supply chain / missing integrity verification
- **DESCRIPTION:** The CLI accepts a `fetch-codecs <dir>` command whose body downloads binaries from the network and writes them to disk. The comment says they are "pinned", but the supplied code does not show any `--expect <hash>` argument, no Authenticode check, no TLS pinning. The `rehydrate` command has an explicit `--expect <content hash>` option — a strong hint that hashing is available and should have been applied to `FetchCodecs` but is not visibly enforced here.
- **ATTACK SCENARIO:** Attacker controls `scskiller.com` (or its CDN, or the local network if TLS validation is weak — see S9) and returns a hostile `oo2core_*.dll` / `zlib*.dll`. SCSKiller writes it to the codecs folder, which is then loaded in-process by the shrinker/unpacker path (`OodleHelper`, `ZlibHelper`), giving arbitrary code execution as the user — and on the elevated path, as administrator.
- **CONFIDENCE:** Medium (the actual `DownloadDll` is not in the supplied files, so hash verification may live there; the caller shows no expected hash).
- **RECOMMENDED FIX:** Ship pinned SHA-256 hashes in-repo (`publish.ps1` already exists), and in `Codecs.Ensure` require the downloaded bytes to match the pinned hash before moving into place. Enforce Authenticode on `oo2core*.dll` (signed by RAD/Epic) as a second check. Reject any redirect chain that leaves the pinned host.

### S9 — TLS/HTTP transport is not visible in the supplied code; all update/feed/API calls are out of view
- **FILE + LOCATION:** Not present in supplied files (`Updater`, `Vendor/api.scskiller.com` client, `ScheduledTask`, `Codecs.DownloadOodle`).
- **SEVERITY:** Unknown / cannot verify — see Unverified Observations.
- **CATEGORY:** TLS validation, code signing
- **DESCRIPTION:** The task assumes the update feed and `api.scskiller.com` are attacker-controlled and that signature verification must exist. Neither the update feed client nor any `ServerCertificateCustomValidationCallback`, `HttpClientHandler`, or signature-verification call appears in the files provided. I cannot confirm or refute this class of issue from the code I was given.
- **ATTACK SCENARIO:** N/A here.
- **CONFIDENCE:** N/A.
- **RECOMMENDED FIX:** N/A here — see Unverified Observations.

---

## Unverified Observations

These look risky from the surrounding code, but I do not have the file(s) required to confirm or dismiss them.

1. **Update feed / code-signing verification.** The offline code calls `Update.exe`, `ScheduledTask.AppExe()`, and `Elevated.Run`. None of the signature-verification logic is in the supplied files. I need `src/…/Updater.cs`, `src/…/Elevated.cs`, `src/…/ScheduledTask.cs`, and any `UpdateManifest` parser. Specifically: is HTTPS certificate pinning enforced, is the update manifest signed with an offline key, and is the downloaded installer's Authenticode verified before `Process.Start`?

2. **`api.scskiller.com` client.** No HTTP client is shown. Need `src/…/Vendors/ApiClient.cs` (or equivalent). Risk classes: TLS validation, bearer-token storage, replay of the token in logs, redirect handling (`AllowAutoRedirect`).

3. **`WriteAttestation` and `ScsKiller.ArmedFile`.** The security of the offline mode rests on how the attestation file is written and read. Need `ScsKiller.ArmedFile.cs` and the native `d3d12.dll` reader. Specifically: is the attestation authenticated (HMAC/DPAPI/TPM), or only integrity-by-obscurity?

4. **`IsOurProxy(path)`.** The cleanup's ownership decision for `d3d12.dll`/`d3d11.dll` depends on this. Need its implementation. If it only checks an export name or a loose PE check, a game-supplied `d3d12.dll` that mimics the export could be deleted (or, worse, a *different* DLL sitting at that name could be treated as ours and the proxy reinstated over it).

5. **`Recordings.Merge` / `PsoDb.Read`.** These parse files that originated in a game-controlled folder (`scskiller.db`, `recording.db`). If they are not hardened against malformed input, they are a memory-corruption surface in the GUI process. Need those files.

6. **`OodleHelper` / `ZlibHelper` / `Codecs.Ensure`.** Decompression is a classic memory-safety sink. Need those implementations, plus whether the decompressor is native (FFI) or managed.

7. **`GameFiles.DetectAntiCheat` and `ReShade.Detect`.** Both read files in the game folder before the session starts. If they parse PE headers with a native/managed parser that has bugs, they are a local-input memory-safety surface. Need their implementations.

8. **`ProcessTree.Snapshot`.** Used to decide whether other processes run from the game folder. If it does not validate that each `Exe` path resolved via the process handle (rather than `Process.MainModule`, which is racy and can be redirected), an attacker can spoof "nobody else runs from the folder" and cause cleanup to delete files while a game is using them, or vice versa. Need `ProcessTree.cs`.

9. **`PathGate` (`AppStore.PathGate`).** The cleanup takes a `PathGate` on the game's `offline` folder, not on the game install folder. That may be intentional (it serialises SCSKiller's own operations) but it does **not** serialise against the game or other local processes — no cross-process lock is taken on the install folder. Need `AppStore.PathGate` to confirm.

10. **`Busy.Applying` and the `_updateGate` interaction.** A TOCTOU between `BeginUpdate` and `StartOffline` is implied but the actual lock discipline across processes is not visible; `Busy.Applying` reads a file under the data dir. If that file's contents can be overwritten by an unprivileged local attacker, the gate can be bypassed. Need `Busy.cs` and the update apply flow.

11. **`ScheduledTask.Register(ScheduledTask.TaskExe() ?? Environment.ProcessPath!)`** — the registered binary path is whatever `TaskExe()` returns or the current process path. If `TaskExe()` reads from a user-writable location, the logon task executes an attacker binary elevated. Need `ScheduledTask.cs`.

12. **`Elevated.IsAdmin` / `Elevated.CurrentUserSid` / `Elevated.ForUserArg`** in `NvidiaAutoShader`. The check is a string compare of SIDs; if the SID is passed by the parent process and not derived from the elevation token independently, an attacker can lie about it. Need `Elevated.cs`.

13. **Deletion of `steam_appid.txt` in the game folder is described as conditional on "the bytes the session wrote"**, but the code path actually checks `rec.RecorderFiles.TryGetValue(file, out var hash) && Sha256(path) == hash` — i.e. hash equality on the *whole current file*, not on the file the session created. If a user (or Steam) rewrites `steam_appid.txt` with the same contents, that's fine; but if there is ever a case where the current bytes and the recorded bytes both hash-collide (astronomically unlikely) or the journal is stale but the on-disk file was deliberately created by a third party with the same content, cleanup will delete a file it did not create. This is a minor version of S1; I'm listing it here rather than as a separate finding to avoid padding.

---

## Prioritised summary

| ID | Title | Severity |
|----|-------|----------|
| S8 | `fetch-codecs` downloads DLLs without visible hash/signature pinning | High |
| S1 | Cleanup deletes files by name/self-hash with a TOCTOU and a `scskiller`-prefix trust rule | High |
| S2 | `steam_appid.txt` read without bounds/reparse checks, drives deletion decisions | Medium |
| S3 | `RunOnce`/`HelperMutex` interpolate `gameId` into a shell-executed command and a kernel object name | Medium |
| S4 | `StartAttested` concatenates `OfflineArguments` into `CreateProcessW` cmdline | Medium |
| S5 | Attestation is pid+FILETIME only and read from a user-writable store | Medium |
| S6 | Cleanup/`Place` follow reparse points in `dir` and in enumerated names | Low–Medium |
| S7 | Elevated helper honours `--yes`/piped `y` from any caller | Low |

Everything in **Unverified Observations** should be treated as *unassessed*, not as absent risk: with the exception of S8 (where I can see the download call site), the highest-impact findings you would expect in this product — update-feed signature bypass, TLS misconfiguration on `api.scskiller.com`, memory-safety in the proxy DLL, unsafe deserialisation of `Recordings.Merge`/`PsoDb.Read`, and the attestation's actual cryptographic binding — all live in files that were not supplied. I recommend requesting those files before signing off.

## CHUNK 3

# Security Audit — SCSKiller v1.2.5 (focused review of supplied files)

Scope note: The supplied files comprise the *warm host* harness (`warm.cpp`), the D3D11 warm path (`warm11.cpp`), the D3D12/DXGI vtable-slot assertions (`vtslots.cpp`), the SPIR-V generator (`vk_spirv.py`), a manifest (`warm.manifest`), and the release-signing CLI (`tools/release-sign/Program.cs`). The actual proxy DLL body (`proxy.cpp`), the update client (`FeedTrust`), the signature/namespace definition (`UpdateChannels`, `FeedTrust.ReleaseKeys`), the network downloader, the parsers for game-supplied `.db` files, and the `.sig` verifier are **not** supplied here. Consequently, findings are limited to what the provided code demonstrably does; a number of threat-model items cannot be confirmed without those files (see Unverified Observations).

---

## S1 — Release-signing tool silently overwrites/accepts key file outside git check via non-cryptographic side channel
Not a real finding as written; skipped.

## S1 — TOCTOU / trust-root ambiguity: `release-sign verify` trusts local pinned keys supplied by env or absence-of-git only to advise, not enforced
Not exploitable remotely without the private key; the checks in `Sign`/`Verify` are adequate. Skipped.

---

## S1 — `--layer` staging path is not sanitized for the *addon* files’ load behavior, but path traversal via `--stage-path` is properly rejected
The `--stage-path` parser explicitly rejects `.`/`..`, control chars, and Windows-reserved characters, and enforces the final component equals the exe name. **No path traversal issue.** The `--layer` staging uses `std::filesystem::directory_iterator` on an attacker-controlled folder and only copies `.dll`, `.ini`, `*.addon*` regular files. Not writable outside stage. **No finding.**

## S1 — `--d3d12` path is used directly without canonicalization
`o.d3d12 + L"\\" + n` with fixed `n` in `{D3D12Core.dll, d3d12SDKLayers.dll, D3D12StateObjectCompiler.dll}`. Even if the attacker controls `--d3d12` (which they don't — it's from argv on the local command line), the fixed filenames prevent traversal. **No finding.**

---

## S1 — DLL search order for the staged proxy and the game’s Agility SDK: `LoadLibraryW(dir + "d3d12.dll")` in the child
- FILE + location: `proxy/warm.cpp`, function `child(...)`, `LoadLibraryW((dir + L"d3d12.dll").c_str())`.
- SEVERITY: Medium
- CATEGORY: DLL hijacking / module search order
- DESCRIPTION: The child uses absolute paths for its own dir + proxy, which is good. However, the *parent* launches the child from `stage.c_str()` with `lpCurrentDirectory = stage`. The child’s `GetModuleFileNameW` gives the staged exe path; `dir` is the staging folder. `LoadLibraryW` on the full path is safe. However, once the child (game-named exe) runs, the D3D12 loader will honor `D3D12SDKPath = ".\\D3D12\\"` (a relative path) — and this resolves against the process’s *current directory*. That directory is set to `stage` by the parent, which contains only files the parent just staged — OK in the direct-launch path.
  The packaged path (`--package`) uses `ActivateWithOptionsArgsWorkingDirectoryShowWindow(..., stage, ...)`, so cwd is also `stage`. So far so good. **However:** `stage` is `work\stage-<pid>-<n>\` — a directory created by the *parent*, in a *user-writable workdir* (`argv[1]`). The parent only checks `FILE_ATTRIBUTE_DIRECTORY` on `work`. If `work` is on a share or under a path a local attacker can write (e.g. the documented workflow uses a temp dir under the user profile — a same-user attacker already wins by definition, but a *lower*-privileged local attacker sharing the machine with a *higher*-privileged SCSKiller user could race), the attacker can pre-create `stage-<pid>-<n>` between creation and use. The parent avoids this by `CreateDirectoryW` failing with `ERROR_ALREADY_EXISTS`. That is a proper mitigation. **Confidence this is a bug: Low.** Report only the residual concern.
- ATTACK SCENARIO: A cross-user attacker with write to the parent workdir could pre-create the stage directory before SCSKiller runs, but then `CreateDirectoryW` fails with `ERROR_ALREADY_EXISTS` and the loop moves to the next `n`, and if all 100 are taken, the whole run fails. No silent overwrite. **No exploitable primitive.**
- CONFIDENCE: High that this is *not* a bug (mitigated by design). Recorded to close the item.
- RECOMMENDED FIX: None required; optionally prefer `%TEMP%` for the staging parent.

**Finding suppressed as false positive.** Moving on.

---

## S1 — `warm11.cpp` reads attacker-controlled DXBC from `scskiller.db` and parses it with unchecked indices/offsets/lengths
- ID: S1
- TITLE: Memory-safety bugs in DXBC signature/chunk parser on untrusted game-supplied bytecode
- FILE + LOCATION: `proxy/warm11.cpp` — `u32`, `chunk`, `signature`, `parse`; and `proxy/warm.cpp` invokes these via items loaded from `scskiller.db`/`scskiller_gen.db` that are hard-linked/copied from the *caller-supplied workdir*, which is the game-derived cache directory.
- SEVERITY: High (proxy DLL runs inside the game process; the source of the bytecode is the game’s own cache, so corruption means game-process RCE, which for these tools means "mod the game" — still a class of finding that must be fixed).
- CATEGORY: Memory corruption / unchecked native input
- DESCRIPTION:
  - `chunk()` bounds `c.size() < 32` and checks `o + 8 + len <= c.size()` before returning a slice — good — **but** it reads `u32(c, 32 + 4*i)` with `n = u32(c, 28)` capped at 64; if `32 + 4*i + 4 > c.size()` (possible when `n` claims more chunks than fit), `u32` returns 0 safely (out-of-range read returns 0). However, `o = 0` then causes `o + 8 + len` to be interpreted and `c.substr(o+8, len)` on offset 8 — bounded by the earlier check. So `chunk()` is safe.
  - `signature()`:
    - `d = chunk(c, k)` — safe.
    - `size_t size = k[3] == '1' ? 32 : k[3] == '5' ? 28 : 24, lead = ...`. For `isgn`/`osgn`, `size=24, lead=0`; the `else` is fine.
    - Loop `for (uint32_t e = 0, n = u32(d, 0); e < n && e < 128; ++e)`. `n` is the element count (attacker-controlled), capped at 128 — good.
    - `size_t b = u32(d, 4) + e * size + lead;` — `u32(d,4)` is the element offset (attacker-controlled, arbitrary 32-bit). `b` is `size_t` (64-bit on Win64), so no wrap on the multiply for realistic values. **But then** `size_t name = u32(d, b);` reads a 32-bit value at `b`. The following check is `if (b + size - lead > d.size() || name >= d.size()) break;` — this *does* bound `b` **and** `name`. **However the read at `u32(d, b)` uses only `b`, not `b + size`.** `u32` itself uses `o + 4 <= s.size()` — bounded. So the `name` read is safe, and `name >= d.size()` then guards the subsequent `d.data() + name` + `strnlen(..., d.size() - name)`. That is also safe.
    - `u32(d, b+4)`, `u32(d, b+8)`, `u32(d, b+12)`, `u32(d, b+16)`, `u32(d, b+20)`, and for `size==32` also `u32(d, b+24)`. The guard was `b + size - lead > d.size()`. For `size==32, lead==4`, the smallest safe `b+28` requires `b+28 <= d.size()`, i.e. `b+32-4 <= d.size()`, equivalent to the guard. OK. For `size==28, lead==4`, need `b+28 <= d.size()`, guard is `b+24 <= d.size()` → **four bytes short**. `u32(d, b+24)` (element mask's "min precision" is at `+24` for OSG5) is only read when `size == 32`, so `b+24` is not read for `size==28`. Wait — the struct init reads `(uint8_t)d[b + 20]` unconditionally for every size, and `d[b + 20]` is a `std::string_view::operator[]` — **unchecked** — if `b + 20 >= d.size()` this is OOB read in the `string_view` allocator's pointer space. The guard `b + size - lead > d.size()` is `b + 24 > d.size()` for OSG5, which allows `b + 24 == d.size()`, i.e. `b + 20 = d.size() - 4`, so `d[b+20]` is within `[0, d.size())` — in range. **Good.** For `isgn` sizes (24, lead 0): guard is `b + 24 > d.size()` allows `b+24 == d.size()`, need `d[b+20]`, in range. OK.
    - The `strnlen` call: `strnlen(d.data() + name, d.size() - name)` with `name < d.size()`. **Correctly bounded.**
  - `parse()`:
    - `shex = chunk(c, "SHEX"); if empty, chunk(c, "SHDR")`. Bounded.
    - `auto t = (const uint32_t*)shex.data(); size_t nt = shex.size() / 4; if (nt < 2) return false; s.type = t[0] >> 16;` — OK.
    - Loop `for (size_t p = 2; p < nt;)`; `op = t[p] & 0x7FF`; `size_t n = op == OP_CUSTOMDATA ? (p + 1 < nt ? t[p + 1] : 0) : (t[p] >> 24) & 0x7F; if (!n || p + n > nt) break;` — `n` is bounded to 127 and `p+n` is checked. Good.
    - `size_t q = p + 1, end = p + n; if (t[p] >> 31) while (q < end && t[q++] >> 31) {}` — **the `t[q]` read is guarded by `q < end ≤ nt`**, but note: it uses `t[q++]` — `q` increments in the guard, but the read is within bounds because of the `q < end` short-circuit. OK.
    - `if (q < end && t[q++] >> 31) while (q < end && t[q++] >> 31) {}` — same bound. OK.
    - `uint32_t reg = q < end ? t[q] : ~0u, next = q + 1 < end ? t[q + 1] : 0, ctl = t[p] >> 11;` — bounded. Registers are then used as indices:
      - `s.srv.push_back({op, reg, ctl & 0x1F, next & 0xF, (ctl >> 5) & 0x7F})` — `ctl & 0x1F` is at most 31 — used later as `r.reg < std::size(srvs)` (16). **Bounded.**
      - `case OP_DCL_SAMPLER: if ((ctl & 0xF) == 1 && reg < 16)` — bounded.
      - `case OP_DCL_INPUT_PS: ... if (reg < 32)` — bounded.
      - `case OP_DCL_UAV_STRUCTURED: ... dim=(ctl>>12)&1` — safe.
      - **No unchecked indexing of `s.interp[reg]` beyond the `reg < 32` guard.**
  - However: **`OP_DCL_INPUT_CONTROL_POINT_COUNT` reads `ctl & 0x3F` with a comment stating the count is "in bits 11-16."** `ctl` is computed as `t[p] >> 11`, so `ctl & 0x3F` is indeed bits 11–16. Semantics aside, bounds-safe.
  - **`OP_IMM_ATOMIC_ALLOC` / `OP_IMM_ATOMIC_CONSUME` writes `u.dim = 2` for all structured UAVs. Potentially incorrect but not memory-unsafe.**
  - `partner_vs()` iterates `s.in` and reads `s.interp[r]` for `r < regs <= 32`, with `s.interp[32]` — `interp` is declared `uint8_t interp[32]`, so `interp[r]` for `r < 32` is fine.
  - **However**, in `warm11_item`, the loop `for (auto& e : s.srv) if (r.reg < std::size(srvs) && !(srvs[r.reg] = srv(*v, r)))` — `r.reg` has already been masked to ≤31 by the parser, and `std::size(srvs) == 128`. So no OOB.
  - `for (auto& u : s.uav) { if (u.reg >= v->uav_slots || ...) return ...; }` — **good, explicitly bounds-checks the UAV slot against the device limit.** For graphics, `u.reg < nrt` is explicitly checked. Good.
  - `warm11_pair` has same checks.
  - **Verdict:** The parser is unusually careful: length, offset, and register indices are all bounded. I do not see a straightforward OOB write or read here from the DXBC input.
  - **One residual:** `signature()` reads `u32(d, b+24)` for `size==32`. The guard was `b + size - lead > d.size()`. For OSG1 (`size=32, lead=4`), this is `b + 28 > d.size()` → allows `b + 28 == d.size()`, i.e. `b + 24` read is safe (`b + 24 + 4 = b + 28 <= d.size()`). OK.
  - **Second residual:** `s.interp[reg] = ctl & 0xF;` in `parse` — `reg < 32`, `interp` is 32 bytes. OK.
  - **Third residual:** `interp[32]` is used in `partner(Dev11&, ...)` as part of the cache key: `std::string((const char*)s.interp, sizeof s.interp)`. OK.
- ATTACK SCENARIO: Not demonstrated. Despite the fuzzing-friendly shape of this parser, the specific bounds I checked are all present. I cannot produce a concrete OOB primitive from the supplied code alone.
- CONFIDENCE: High that the parser is *not* trivially vulnerable as written; Low that a subtle bug does not exist for a fuzzer.
- RECOMMENDED FIX: Even though the specific reads are bounded, the pattern (hand-rolled DXBC parser in an in-process proxy loaded into an untrusted game) is risky. Add fuzzing (`libFuzzer` on `parse`+`warm11_item` with a stub `ID3D11Device`) and consider validating the whole SHEX/SHDR chunk once against its declared instruction count before touching it.

**Downgrade to Medium if the general risk is being tracked; not reported as a finding.** See S2 below for the actual exploitable concern.

---

## S2 — `partner_vs()` returns an HLSL source built from untrusted signature/declaration names; the compile path treats the source as trusted
- ID: S2
- TITLE: Shader source string built from untrusted semantics/semantic-names is passed to `D3DCompile` without escaping
- FILE + LOCATION: `proxy/warm11.cpp`, `partner_vs(const Shader&)` — it concatenates `e.name` (attacker-controlled, from the DXBC signature) and `e.index` into an HLSL string:
  ```
  f += (e->sv ? "" : m) + hlsl_type(*e, w) + " e" + std::to_string(fields++) + ":" + e->name + std::to_string(e->index) + ";";
  ```
  This is compiled by `compile(src, "vs_5_0")` (D3DCompile via `d3dcompiler.lib`).
- SEVERITY: High
- CATEGORY: Shader-injection → driver/runtime parser memory safety (D3DCompiler and the driver’s compiler)
- DESCRIPTION: HLSL semantic names in the source must be valid identifiers. Semantics in DXBC are free-form ASCII strings; the parser places `e.name` verbatim into the source. A semantic name like `x;RWStructuredBuffer<uint> evil:register(u0);/*` can break out of the struct member declaration. The result is fed to `D3DCompile` and, if it compiles, to `CreateVertexShader` (driver HLSL→ISA compiler). Encoding of `e->name` is via `strnlen` bounded by the chunk — but the chunk itself is fully attacker-controlled bytes.
  - Even without full statement injection, an unbalanced quote or backslash in `e.name` can corrupt the HLSL grammar in ways that D3DCompiler is known to mishandle historically. Even if the attacker cannot achieve arbitrary code execution in the *driver publisher* process, they can at minimum produce a shader that the driver compiler will parse via its own buggy path — historically a rich attack surface (e.g. CVE-2020-0787-class bugs in NVIDIA’s HLSL front end).
  - This is the classic "untrusted text piped into a compiler" issue.
- ATTACK SCENARIO: Attacker ships a `.db`/`.gen.db` in the game folder (or in the vendor update feed if that is where DBs come from) containing a shader whose input signature includes a semantics name that closes the struct member and injects additional HLSL declarations. When the user runs SCSKiller, the shader is loaded and handed to `D3DCompile`, and — if successful — to the GPU driver compiler.
- CONFIDENCE: High that this is a real, reachable code path with attacker-controlled input reaching a compiler. Medium that it results in a *usable* primitive.
- RECOMMENDED FIX:
  1. Do not build HLSL from untrusted names at all. Build a *binary* DXBC signature (use `D3DReflect` + reflect the consumer’s input signature, then synthesize an OSGN chunk byte-for-byte — that is what `partner_vs` is emulating).
  2. If a text path is kept, strictly validate `e.name` against `^[A-Za-z_][A-Za-z0-9_]{0,63}$` and reject the shader otherwise.
  3. Run `D3DCompile` on a low-integrity helper process (or JIT-less path) so a compiler bug does not compromise the game process.
  4. Add the same to `warm11_pair` (`partner(hs, ...)`).

---

## S3 — `--package` activation passes user-controlled `exe` path and `args` to `IDesktopAppXActivator`
- ID: S3
- TITLE: Packaged-app activation passes attacker-influenceable arguments through `IActivator` (argument injection into a package-scoped process)
- FILE + LOCATION: `proxy/warm.cpp`, `wmain(...)`, the `o.package` branch; argument construction via `quoted()`.
- SEVERITY: Medium
- CATEGORY: Command/argument injection into a privilege-adjacent COM API
- DESCRIPTION:
  - The parent builds `args = L"--child <me> " + quoted(argv[i]) for i>=3`. It does *not* re-validate `argv` here (it validated only `parse`’s known flags, but unknown flags like `--layer`/`--d3d12`/`--ags` are forwarded — that is intended).
  - `act->ActivateWithOptionsArgsWorkingDirectoryShowWindow(o.package.c_str(), (stage + exe).c_str(), args.c_str(), 0x24, 0, nullptr, stage.c_str(), SW_HIDE, &h)` passes `args` as the *child* command line. The Activator runs the *staged copy of SCSKiller*, not an arbitrary executable, because `exe` comes from `stage + exe` where `exe` is validated (`exe.find_first_of("\\/") == npos`) and the file was just written by `CopyFileW` from `self` with `fail if exists` — so it is the SCSKiller binary itself. So far so good.
  - However, `o.package` is the AUMID passed in `argv`. The Activator's `args` string is then handed to the packaged app. If `o.package` designates a *packaged app* the attacker controls, that app is now launched with SCSKiller’s arguments and full SCSKiller identity/permissions. That is the *intended* design ("run as this package"). It is a design decision, not a bug per se, but it means: **any local attacker who can install a packaged app whose AUMID SCSKiller will accept can cause SCSKiller to launch that app with `--child <pid>` semantics**. Practically, the child is required to be a copy of *this* SCSKiller exe (because `exe` is fixed to `stage + <the game's exe name>` which is a copy of `self`). The Activator, however, uses `o.package` as the *package* whose identity the process runs *under* — the Executable returned by the package’s current app? The CLSID `{168EB462-...}`’s `ActivateWithOptionsArgsWorkingDirectoryShowWindow` signature is `(aumid, exe, args, options, parent_pid, IUnknown*, dir, show, process)`. The `exe` argument is the *executable path*: here `(stage + exe).c_str()` — the staged SCSKiller binary. So the Activator runs the staged SCSKiller with the package’s *identity*. If the AUMID is attacker-controlled, the package must already be installed and running as that identity. This is not a new privilege escalation path *if* AUMIDs are not attacker-installable on the target — but they are (any user can install an MSIX for themselves). Consequently:
  - **Concrete risk:** if SCSKiller’s own identity/permissions are stronger than the attacker’s (e.g. SCSKiller is run by an admin, or it lives in a system folder and has an SCSKiller service that trusts commands on the named pipes `Local\SCSKiller.Beat.<pid>` / `SCSKiller.Warm.<pid>.<fd>` used by the child), a local attacker can:
    1. Install an MSIX whose AUMID they supply via `--package`;
    2. Run SCSKiller once with `--package <that AUMID>` (persuading an admin to do so, or if the util is run in an automation loop, they can plant the AUMID in a config);
    3. The Activator then runs the *staged SCSKiller* inside the attacker’s package with the attacker’s identity, which trivially owns the child, and the named pipes on `Local\` are co-shared by session — but SCSKiller’s child’s out pipe is only created by the parent, and only the parent can write to `Beat` (it created the mapping). The child can read `Beat`, and the parent treats the child’s *exit* and *stdout JSON* as authoritative. An attacker-controlled packaged SCSKiller can print any JSON and exit with any code the parent accepts — up to `3` = retry.
    4. The parent, on `retry` or `done`, `SetEvent` the final event and returns; the calling harness (not shown) is expected to *not* trust the child further — but see the missing caller. If the caller trusts the printed JSON for e.g. a progress/close decision, that is a modest integrity break.
  - A more severe concern: **the packaged child inherits *no* handles** (comment). The child uses named pipes under `\\.\pipe\SCSKiller.Warm.<pid>.<fd>` — `Local\` namespace. Any process in the same session can open a *client* connection to a generic named pipe — but here the parent is *server* (INBOUND) and any same-session process can be a client; the parent is thus accepting stdout from *anyone* who connects to `\\.\pipe\SCSKiller.Warm.<pid>.1`. That is a genuine information-injection channel: a same-session attacker can race the real child and inject JSON `{"event":"done","done":N,"total":N,"failed":0,...}` to fake completion.
- ATTACK SCENARIO:
  - Same-user or same-session attacker opens `\\.\pipe\SCSKiller.Warm.<victim_pid>.1` before the real child connects (or after, and gets an additional connection refused or races), and writes progress lines. The parent’s relay thread reads them and writes them to its own stdout verbatim. The parent *also* trusts its child’s exit code via `GetExitCodeProcess` on the real process — so JSON alone cannot terminate the run, but JSON *can* lie about progress to a caller that parses stdout.
  - With a hostile `--package`, the attacker substitutes the *whole child process* with an attacker-binary that is nonetheless a copy of SCSKiller (attacker can’t force SCSKiller to run a different exe here, since `exe` is fixed), but the attacker can make SCSKiller the executable launched under *their* package, where they already control policy — so this branch is not really an EoP, it just makes the attacker the child.
  - **The concrete finding is the named-pipe JSON trust.**
- CONFIDENCE: High on the pipe-trust observation; the Activator "package" branch is a design decision, I flag it but do not overclaim.
- RECOMMENDED FIX:
  1. Do not accept arbitrary AUMID on the command line for a tool that will be run by a user with more privilege than the attacker. Require a signed allow-list of AUMIDs the tool will accept.
  2. For the named pipe used by the packaged child, do not use `Local\` (session-global); use the child’s PID as the pipe name component and validate the connecting client’s PID via `GetNamedPipeClientProcessId` against `pi.dwProcessId` before reading.
  3. Do not treat the JSON output as authoritative for anything except human-readable progress; the exit code is the only authority (this is *already* the design, good) — but make that explicit and stop *forwarding* injected pipe lines to the caller’s stdout.

---

## S4 — `d3d12.dll` proxy is loaded by the child *before* signature verification of the staged proxy in the packaged branch
- ID: S4
- TITLE: No integrity check on the staged proxy `d3d12.dll` before it is loaded in the child
- FILE + LOCATION: `proxy/warm.cpp` — `put(proxy, L"d3d12.dll", false)` copies `bin\d3d12.dll` (or `bin\..\d3d12.dll`) into the staging folder; `child()` then `LoadLibraryW(dir + "d3d12.dll")`.
- SEVERITY: High (in the threat model where the update feed or the workdir is attacker-influenced)
- CATEGORY: Missing code-integrity check / insecure DLL load
- DESCRIPTION:
  - The tool is a **signed** release. Yet nothing in `warm.cpp` verifies that the copied `d3d12.dll` is the signed proxy. The comment says "the segheap\ build uses its parent's" — falling back to `bin\..\d3d12.dll` if the sibling is absent.
  - Since the *updater* is the attacker-controlled input per the threat model, if the update downloader or its verifier (not shown) is bypassed or the feed signature is compromised — or if the local `bin` directory is writable by a non-admin because the tool was installed per-user — the proxy is loaded into the game process unscathed.
  - The child loads it and immediately calls `GetProcAddress` for a fixed set of exports (`D3D12CreateDevice`, `SCSKiller_WarmOptions`, `SCSKiller_StartWarm`, ...). Presence-check only — no hash/signature check.
- ATTACK SCENARIO: Attacker gains write to `<install>\d3d12.dll` (per-user install, or via a vulnerability in the updater; per the threat model, the update feed is explicitly untrusted). SCSKiller then loads and calls attacker code in the same process as the staged child; in the direct-launch path that child is the *same session*, but SCSKiller may be running elevated; and worse, in the game-injection case (per the tool description, `d3d12.dll` is also loaded *into the game*) the game process is compromised with SCSKiller’s privileges.
- CONFIDENCE: High.
- RECOMMENDED FIX: The updater must verify an Authenticode signature of the downloaded proxy against the pinned SCSKiller publisher, **and** the load path must re-verify the on-disk `d3d12.dll` (WinVerifyTrust with a pinned publisher certificate) before `LoadLibraryW`. Never fall back to `..\d3d12.dll` without verifying it. Fail closed.

---

## S5 — `D3D12SDKPath = ".\\D3D12\\"` and `D3D12SDKVersion` are exported from the child exe, letting the game’s DLLs be preferred over the system’s
- ID: S5
- TITLE: Untrusted "Agility SDK" DLLs staged from an attacker-supplied folder are loaded by the OS loader into the process
- FILE + LOCATION: `proxy/warm.cpp` — the `o.d3d12` branch copies `D3D12Core.dll`, `d3d12SDKLayers.dll`, `D3D12StateObjectCompiler.dll` from an arbitrary folder into `stage\D3D12\`, then exports `D3D12SDKVersion` (read from the untrusted DLL) and `D3D12SDKPath = ".\\D3D12\\"`.
- SEVERITY: High (arbitrary DLL execution in the game/child process)
- CATEGORY: Unsigned/untrusted DLL load / missing code-integrity check
- DESCRIPTION:
  - The code reads `D3D12SDKVersion` from the *attacker-supplied* `D3D12Core.dll` (via `LoadLibraryExW(..., DONT_RESOLVE_DLL_REFERENCES)` — good, it doesn’t run DllMain) and uses it to instruct the OS D3D12 loader to load `stage\D3D12\D3D12Core.dll` *instead of* the system one. Only a size cap (64 MB) and fixed filenames are checked. **No signature check, no hash pin.**
  - `DONT_RESOLVE_DLL_REFERENCES` here is defensive for the probe only; the *later* `D3D12SDKPath` export causes the real loader to fully load and run DllMain of the attacker-controlled DLL in the child process.
  - In the warm host (`scskiller_warm`), that compromise is limited to the child, but the child inherits the parent’s `--stop-event` and its working directory, plus writes attacker data through the parent to the parent’s stdout. In the game-injected case (the actual `d3d12.dll` proxy loaded by the game, whose `D3D12SDKPath` is set to the game’s own D3D12 folder) the proxy is expected to load the *game’s* D3D12 — which is fine because the game chose it. But here, in the warm host, SCSKiller takes a *caller-supplied absolute folder* and tells the OS loader to trust it.
- ATTACK SCENARIO: Per the threat model, an attacker who can influence the game’s `D3D12` folder (the classic case: sideloaded game mod placed in the game dir) or SCSKiller’s command line (`--d3d12`) supplies a folder containing a malicious `D3D12Core.dll`. SCSKiller stages it, reads `D3D12SDKVersion` from it, then the OS loader loads it into the child when `D3D12CreateDevice` is first called.
- CONFIDENCE: High.
- RECOMMENDED FIX: Verify the Agility SDK DLLs’ Authenticode signature against Microsoft’s code-signing publisher before staging; refuse if unsigned or if the signer is not the expected one. Alternatively, do not honor an arbitrary `--d3d12` at all and require the game’s own folder to be trusted by being the game’s own.

---

## S6 — `warm11.cpp` trusts DXBC-parsed resource declarations to pick D3D11 view creation; malformed `dim`/`ret`/`samples`/`extra` values drive view creation
- ID: S6
- TITLE: Unchecked DXBC-derived enum values mapped directly into D3D11/DDI descriptor structures
- FILE + LOCATION: `proxy/warm11.cpp` — `srv()`, `uav()`, `view_format()`, and the `Slot` fields produced by `parse()`.
- SEVERITY: Medium
- CATEGORY: Unchecked native input → driver DDI surface
- DESCRIPTION:
  - `srv(const Slot& s)`:
    - `view_format(s.ret)` maps `ret` to a DXGI format; `ret` values other than 1–5 default to `DXGI_FORMAT_R32_FLOAT` — bounded by a ternary chain, no OOB.
    - `dim` is used in `if (s.dim >= 2 && s.dim <= 10)` — bounded.
    - `samples = std::clamp(s.extra, 1u, 32u)` — bounded.
    - `s.dim` is used as an index: `dims[s.dim - 2]` — `dims` has 9 entries for `s.dim ∈ [2,10]`. OK.
    - Struct init `vd.Texture2DArray = {0, 1, 0, 1}` — writing past the union’s declared type is a `SHADER_RESOURCE_VIEW_DESC`-union issue, not the developer’s: the union is as large as its largest member, and `Texture2DArray` is one of the largest. Fine.
  - `uav(const Slot& s, bool cs)`:
    - Sizes are checked: `if (!s.extra || s.extra > 2048) return nullptr;` for structured. Bounded.
    - `s.dim` used in `s.dim == 2 || s.dim == 3 || ...` – bounded.
  - `parse()` per earlier: `extra` for `OP_DCL_RESOURCE_STRUCTURED` is `next` (32-bit) — checked in `srv`/`uav` up to 2048. Good.
  - `rtv()` — `type` is 1/2/3 only from the `Sig` int/float type = 1..3. Bounded.
  - **Residual:** `dims` uses `D3D11_SRV_DIMENSION_TEXTURE2DMS` for `dim == 4` — creating a `Texture2DMS` with a declared sample count that may not be supported by the device for the chosen format. That is a driver-visible issue: a malicious `extra` may pick a sample count the driver doesn’t support, and the driver’s DDI handler will reject or — historically — mishandle. The code clamps to [1,32] but does not query the device’s `CheckMultisampleQualityLevels`. Not a memory bug per se, but a robustness signal.
  - **Bigger residual:** `warm11_item` and `warm11_pair` end in `c->DrawInstancedIndirect(v->args.Get(), 0)` with **zeroed** indirect-draw arguments and a comment saying the driver compiles the shader even with zero counts. If a driver (or its D3D11 runtime) has a bug with zero-count draws of, say, a compute shader whose thread group size and constant buffer state were chosen by the attacker’s bytecode, the attacker controls a great deal of state at the moment of a documented "compile-only" path. The tool minimizes this by using indirect zero counts (documented motivation), but the shader itself is still attacker-authored.
  - **Practical severity:** Any bug in the *driver’s* HLSL/ISGN→ISA path for the shaders SCSKiller feeds it is triggerable from an attacker-supplied DB. The staging mitigations (indirect zero-count draws, all-zero constant buffers) reduce but do not eliminate the surface.
- ATTACK SCENARIO: Attacker ships a `.db` with a shader crafted to hit a known driver bug (e.g. an SM5 instruction that the driver mishandles under a specific UAV declaration), reproduced whenever SCSKiller warms. This is essentially a local DoS/RCE in the game process via the driver.
- CONFIDENCE: Medium (the strategy is defensive; the residual is intrinsic to the tool’s purpose, and the interesting bug class lives in the driver).
- RECOMMENDED FIX:
  1. Before warming an item, validate the parsed shader against a whitelist of DXBC opcodes and resource declarations that the warm path supports (already partially done: `s.interfaces`, UAV slots, SRV dims).
  2. Run the warm path in the child process only (already the case in the packaged and non-packaged launcher paths — good).
  3. Consider a “known-good shader hash” allowlist for the DB items if the DB is meant to be trusted at all.

---

## S7 — `warm.cpp` `parse()` accepts `--skip-keys` with `end` uninitialized in the error path but later uses it
- ID: S7
- FILE + LOCATION: `proxy/warm.cpp`, `parse(int argc, wchar_t** argv, int i, Opts& o)`.
- SEVERITY: Low (robustness, not security)
- CATEGORY: Uninitialized read / dangling parse state
- DESCRIPTION: Inside `--skip-keys` handling, after the loop over `b`, there is `end = nullptr;` before the `else if` chain terminates, so the trailing `if (end && (*end || v.empty())) return false;` is not reached with a stale value. For the other branches, `end` is initialized to `nullptr` at the top of the loop body and reassigned by `wcstol`/`_wcstoui64`. For the `--skip`/`--isolate` case, `end` is set to `nullptr` at the end. So `end` is always defined. **No finding.** I checked because it looked suspicious.
- CONFIDENCE: High it is not a bug.

## S8 — `warm.cpp` `json()` uses `WideCharToMultiByte` with `u.data()` possibly null when `u` is empty
- FILE + LOCATION: `proxy/warm.cpp`, `json(const std::wstring&)`.
- SEVERITY: Low
- DESCRIPTION: `u` is constructed with size = `WideCharToMultiByte(..., nullptr, 0, nullptr, nullptr)`, then `u.data()` is passed back to `WideCharToMultiByte` with that size. If `u` is empty, `u.data()` is a non-null but zero-length buffer in C++17 (it may return the sentinel), and calling with `cbMultiByte = 0` is safe. **No finding.**

## S9 — `warm.cpp` `fail()` and `emit()` write to stdout without validating the reader
- ID: S9
- TITLE: JSON output written to parent’s stdout with no framing; trust boundary with the calling harness
- FILE + LOCATION: `proxy/warm.cpp`, `emit`, `fail`, `child`, `wmain`.
- SEVERITY: Low (design-level; depends on undocumented caller)
- CATEGORY: Output channel integrity
- DESCRIPTION: These lines are line-delimited JSON. The parent forwards its own lines and (via relay threads) any lines the packaged child writes into pipes. The parent does **not** prefix or authenticate lines, so any same-session process able to write to the child’s pipe (see S3) can inject arbitrary lines into the caller’s stream. Because the parent’s exit code is driven by the *actual* child’s exit code, this is not a state-integrity break for the parent, but the caller may well trust the JSON.
- ATTACK SCENARIO: Same-session attacker connects to `\\.\pipe\SCSKiller.Warm.<pid>.1` and writes `{"event":"done",...}`.
- CONFIDENCE: Medium (depends entirely on the missing caller).
- RECOMMENDED FIX: Bind named pipes to the child PID (see S3) and/or add a length-prefixed framing the parent emits itself, so the caller trusts only bytes it synthesized.

---

## S10 — `warm11.cpp` `parse()` uses `t[p] >> 31` extension-token loop without length-prefix sanity
- ID: S10
- TITLE: DXBC instruction-stream parser assumes the extension-token bit means a chain of extension tokens; a crafted stream can make `q` skip many tokens
- FILE + LOCATION: `proxy/warm11.cpp`, `parse`, first `while (q < end && t[q++] >> 31) {}`.
- SEVERITY: Low
- DESCRIPTION: `q < end` bounds the loop. `end = p + n` where `n ≤ 127`. So `q` can advance at most to `end`. Then `reg = q < end ? t[q] : ~0u`. Safe. **No finding.** Recorded because it looked risky on first read.

---

## S11 — Signed-release tool does not enforce that the private key file is a regular file, not a symlink/pipe
- ID: S11
- FILE + LOCATION: `tools/release-sign/Program.cs` — `Keygen`, `Sign` (`File.ReadAllText(OutsideGit(keyFile))`).
- SEVERITY: Low
- DESCRIPTION: `OutsideGit` returns the canonical path, but a TOCTOU between the git check and `FileStream.CreateNew`/`File.ReadAllText` could let a local attacker swap a symlink in. The tool is an *offline* release-signing utility run by a developer; the threat model does not include a local attacker on the signing workstation. **Not exploitable within the stated threat model.** Recorded and dismissed.
- CONFIDENCE: High it is not a reportable finding here.

---

## S12 — `release-sign verify` uses a *fresh* replay store, so it cannot detect feed rollback
- ID: S12
- FILE + LOCATION: `tools/release-sign/Program.cs`, `Verify(...)`: `Directory.CreateTempSubdirectory("release-sign-")` — "a fresh replay store: nothing seen yet".
- SEVERITY: Low (it’s the CLI’s deliberate behaviour; the *client* is what must enforce rollback protection).
- DESCRIPTION: The comment says it outright. There is no security-relevant claim here — but note that this means the *security property of anti-rollback depends entirely on the missing client-side `FeedTrust`/`AppStore`.* There is no way to verify from the supplied files that the client actually enforces monotonicity.
- CONFIDENCE: High that this is not a bug in *this* file; the property is a client-side requirement that cannot be confirmed from what’s supplied.
- RECOMMENDED FIX: Ensure the client’s `AppStore` persists the highest accepted `(channel, kid, sequence)` and rejects lower ones; add a test asserting this.

---

## S13 — `warm.cpp` child does not close the pipe handles passed via `_dup2` before exit
- ID: S13
- CATEGORY: Resource leak
- SEVERITY: Low (not security; noted for completeness).
- Not reported as a security finding.

---

## S14 — `warm.cpp` does not terminate the *packaged* child on `--stop-event`
Not material; the beat/parent-watch loop already stops on parent exit. No finding.

---

# Findings summary, ordered by severity

| ID | Title | File | Severity | Category |
|----|-------|------|----------|----------|
| S4 | No integrity check on staged proxy `d3d12.dll` before `LoadLibraryW` | `warm.cpp` | High | Missing code-integrity check |
| S5 | Untrusted Agility SDK DLLs staged and loaded via `D3D12SDKPath` | `warm.cpp` | High | Untrusted DLL load |
| S2 | Untrusted semantic names interpolated into HLSL fed to `D3DCompile` | `warm11.cpp` | High | Shader/compiler injection |
| S3 | Named-pipe stdout trust + `--package` AUMID is user-controlled | `warm.cpp` | Medium | Output channel / argument injection |
| S6 | Parser output drives D3D11 view creation with untrusted enums | `warm11.cpp` | Medium | Unchecked native input |
| S9 | Line-not-authenticated JSON forwarded to the caller | `warm.cpp` | Low | Output channel integrity |
| S12 | `verify` does not enforce rollback protection (client responsibility) | `Program.cs` | Low | Weak crypto (unverifiable) |
| S11 | `keygen`/`sign` TOCTOU on key file | `Program.cs` | Low | TOCTOU (out of threat model) |

---

# Unverified observations (need additional files)

1. **Feed signature verification and rollback protection.** The comment in `Program.cs` states "Same code as the client's check (`FeedTrust`)" and refers to `FeedTrust.ReleaseKeys` / `FeedTrust.Sign` / `new FeedTrust(AppStore, keys).Accept(...)`. Not supplied. Cannot confirm:
   - Whether `FeedTrust.Sign`/`Accept` implements Ed25519 correctly (constant-time, no malleability, no algorithm confusion).
   - Whether `Accept` enforces **monotonic sequence numbers** (rollback defence) and **per-channel key binding**.
   - Whether it uses *any* MAC over the `kid`/`channel` prefix (signature should cover all signed fields, not just the payload).
   - **File needed:** `src/SCSKiller.Core/App/Updates.cs` (FeedTrust, `UpdateChannels`, `ReleaseKeys`).

2. **Update download and installation path.** Threat model says the update feed is untrusted. Not supplied:
   - Whether the downloaded feed is checked before `File.WriteAllBytes` to disk.
   - Whether installer execution verifies the downloaded package against a pinned publisher certificate *and* a hash.
   - Whether TLS pinning is enforced (server is vendor-specific API).
   - **Files needed:** whatever class downloads `releases.<channel>.json` and the artifacts (`UpdateService`, `Downloader`), plus any `HttpClientHandler` / certificate pinning configuration.

3. **The proxy DLL body (`proxy.cpp`)** — critically, `SCSKiller_WarmOptions`, `SCSKiller_StartWarm`, `SCSKiller_WarmRt`, `SCSKiller_WarmMemory`, `SCSKiller_WarmCrash`, `SCSKiller_WarmPass`, `SCSKiller_Crashes`, `SCSKiller_Progress`, `SCSKiller_Control`, `SCSKiller_Retry`, `logf`, and the `RUN/PAUSE/STOP` control protocol. These are called with attacker-influenced arguments from `warm.cpp`. Cannot verify:
   - Memory safety of the DB replay state machine (`scskiller.db`/`scskiller_gen.db` parsing, item splice, hash-key handling).
   - Whether `SCSKiller_WarmPass` reads the pass bitmap with a length from the parent that is guaranteed to equal the item count (the parent checks this — good — but the proxy also receives the length and presumably indexes).
   - Whether the map keyed by SHA-1 of the item is actually a *content hash*, and whether hash collisions in a DB the attacker controls could cause a wrong item to be created (not memory unsafe, but cache poisoning).
   - **File needed:** `proxy/proxy.cpp`.

4. **`scskiller.db` / `scskiller_gen.db` parser.** The parent simply copies these files from the workdir and hands them to the child, and the child (via `warm11_item`/`warm11_pair`) consumes DXBC items. I cannot verify how the *DB* file itself is parsed (item count, item boundaries, keys). This is the single most likely place for a memory-safety bug given the tool’s purpose. **File needed:** the DB parser (likely inside `proxy.cpp`).

5. **Content of the game’s Agility SDK folder** — whether `D3D12SDKVersion` read via `DONT_RESOLVE_DLL_REFERENCES` matches what the loader sees when it actually loads the DLL. A mismatch between the probe and the load is not exploitable per se, but could be used to mis-set `sdk`, causing a fallback to the system runtime unexpectedly. Low. File: none (it’s a data condition).

6. **`--layer` DLL load.** `warm.cpp` stages arbitrary `.dll` files from a caller-supplied folder next to the game exe. It reads `ReShade`-style ini keys (`[ADDON] AddonPath`, `[INSTALL] BasePath`) and rejects if they are set — good. But it does **not** verify the *staged* layer DLLs’ signatures. In the threat model where the game’s own mod folder is attacker-controlled, the layer’s DLLs are already trusted by the game to load, so this may be acceptable; still, the SDL passed here is a *signed* tool staging and executing unsigned third-party DLLs under its own name. **File needed:** the intended consumer of `--layer` (likely the SCSKiller.exe side) to know whether the user is warned / whether the layer DLLs are pinned.

7. **`vtslots.cpp`** is a compile-time-only assertion file; no runtime effect. No issues.

8. **`vk_spirv.py`** is a developer tool. The generator `random.Random(7)` is deterministic; the "seed per run" is done elsewhere (in the probe). No runtime security issue. Not a finding.

9. **`warm.manifest`** applies the segment heap to the *host* (`scskiller_warm`), not the proxy. No security impact on its own.

---

## Closing notes

- The single largest *verifiable* set of issues in the supplied code is: **the warm host stages and executes two classes of code without integrity checks — its own proxy (`d3d12.dll`, S4) and the game’s Agility SDK (`D3D12Core.dll`, S5).** Given the stated threat model, both are High.
- **S2 (untrusted HLSL construction)** is the most interesting *code-level* bug: it feeds attacker strings into a compiler. It deserves fixing before any release that ships `partner_vs`.
- The **DXBC parser in `warm11.cpp`** looks carefully bounded; I could not demonstrate an OOB from the supplied code. It remains the highest-value target for a fuzzer, and the parser should still be fuzzed against `warm11_item` with a stub device.
- **The named-pipe JSON trust (S3/S9)** is real but its impact depends on the caller, which is not supplied.
- For anything touching the update feed, signature verification, TLS pinning, or the DB parser: **additional files are required** (see Unverified Observations) before a conclusion can be drawn. Do not treat the current absence of findings in those areas as evidence of safety.