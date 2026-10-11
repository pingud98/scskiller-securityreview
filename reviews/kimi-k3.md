## CHUNK 0

# SECURITY AUDIT: SCSKiller v1.2.5

## FINDINGS

---

**ID:** S1
**TITLE:** Ed25519 public keys embedded in source code (unverifiable trust root)
**FILE:** src/SCSKiller.Core/App/Updates.cs — `FeedTrust.ReleaseKeys` (static readonly dictionary)
**SEVERITY:** High
**CATEGORY:** Weak crypto / Trust anchor
**DESCRIPTION:** The two Ed25519 release public keys (`rel-a`, `rel-b`) are hardcoded as base64 strings in the shipped binary. While this is standard practice for key pinning, the keys are the *sole* trust anchor for the entire update system. If either private key is compromised, an attacker can sign malicious feeds that pass all verification. There is no key rotation mechanism visible in the supplied code, no certificate chain, and no revocation mechanism. The comment says keys are "generated offline by the maintainer" but there is no mechanism to distribute new keys to existing installs other than shipping a new binary (which itself must be signed by the old key).
**ATTACK SCENARIO:** Compromise of the maintainer's offline signing key (rel-a or rel-b) allows permanent, silent pushing of malicious updates to all users on all channels. Without a rotation/revocation mechanism, the only remediation is manual reinstallation.
**CONFIDENCE:** High (that this is the design; the risk is inherent to single-key pinning without rotation)
**RECOMMENDED FIX:** Implement key rotation support: allow feeds to carry a "next-keys" payload signed by current keys, or support a threshold signature scheme (e.g., 2-of-3). At minimum, document the key rotation procedure and ensure the `kid` field lookup can handle new keys delivered via a trusted channel.

---

**ID:** S2
**TITLE:** Feed replay protection uses only `signed_at` timestamp comparison
**FILE:** src/SCSKiller.Core/App/Updates.cs — `FeedTrust.Accept()` method
**SEVERITY:** Medium
**CATEGORY:** Weak crypto / Replay
**DESCRIPTION:** The replay protection compares `signed_at` timestamps: a feed is rejected only if its `signed_at` is strictly older than the newest previously seen for that channel. This means an attacker who compromises a signing key can sign a feed with a `signed_at` far in the future, which will be accepted and will also block all legitimate feeds until that future date is reached (a denial-of-service on the update channel). Additionally, `DateTimeOffset.TryParse` with `DateTimeStyles.AssumeUniversal` is used, so timezone manipulation in the timestamp string could affect ordering.
**ATTACK SCENARIO:** With a compromised key, sign a feed with `signed_at` = "2099-01-01T00:00:00Z". All subsequent legitimate feeds will be rejected as "older than one already seen" until 2099, permanently blocking updates.
**CONFIDENCE:** High
**RECOMMENDED FIX:** Reject feeds with `signed_at` more than a small window (e.g., 24 hours) in the future. Consider using a monotonically increasing sequence number instead of timestamps.

---

**ID:** S3
**TITLE:** `StagedUpdate.Refused` iterates feeds but does not enforce that the record's own channel feed is present
**FILE:** src/SCSKiller.Core/App/Updates.cs — `StagedUpdate.Refused()` method
**SEVERITY:** Medium
**CATEGORY:** Insufficient validation
**DESCRIPTION:** The `Refused` method checks that each feed in the dictionary verifies and that at least one lists the package. However, it does not require that the feed for `this.Channel` itself is present in `Feeds`. An attacker who can write to the data directory could craft a staged update record claiming to be for the "stable" channel but only include a signed feed for "internal" (which passes the `c <= at` check since internal has index 3 and stable has index 0... wait, actually the check is `c > at` returns error, so for Channel="stable" (at=0), any channel with c>0 would be rejected. Let me re-examine.

Actually, looking more carefully: `Array.IndexOf(UpdateChannels.All, channel) is var c && (c < 0 || c > at)` — this rejects feeds from channels *after* the staged channel. For Channel="internal" (at=3), all channels 0-3 are accepted. For Channel="stable" (at=0), only stable (c=0) is accepted. The logic is correct for the channel hierarchy. However, the `listed` flag is OR'd across all feeds, so if the staged channel is "internal" and the attacker's feed for "alpha" lists the package, it passes even without an "internal" feed. This is by design per the comment ("the channels before it"), so this is not a vulnerability per se.

Upon deeper analysis, this is actually correctly implemented for the stated design. **Withdrawn as a finding.**

---

**ID:** S3 (revised)
**TITLE:** `FeedClient.SendAsync` sends bearer token to any non-stable channel host without TLS verification check
**FILE:** src/SCSKiller.Core/App/Updates.cs — `FeedClient.SendAsync()` method
**SEVERITY:** Medium
**CATEGORY:** Auth token handling / TLS validation
**DESCRIPTION:** The `SendAsync` method attaches the Bearer token to any request where `channel != UpdateChannels.Stable`. The URL is constructed via `UpdateFeeds.Feed()` which uses `RouteFailover.Default.Primary` for non-stable channels. The `RouteFailover` class is not supplied, so the actual URL is unknown. If `RouteFailover.Default.Primary` can ever resolve to a non-HTTPS URL, or if the failover mechanism can be influenced, the bearer token would be sent to an unintended host. Additionally, the `HttpClient` is constructed with `new HttpClient(handler, disposeHandler: false)` — the `handler` parameter is `RouteFailover.Default`, which is an `HttpMessageHandler`. If this handler does not enforce TLS certificate validation (or disables it), tokens could be intercepted.
**ATTACK SCENARIO:** If `RouteFailover` can be influenced (e.g., via DNS or the `SCSKILLER_API` environment variable) to point to an attacker-controlled server, the bearer token is sent in the `Authorization` header to that server.
**CONFIDENCE:** Medium (depends on `RouteFailover` implementation, which is not supplied)
**RECOMMENDED FIX:** Explicitly validate that the URI scheme is HTTPS before attaching the Authorization header. Add a check: `if (url.Scheme != "https") throw new SecurityException("non-HTTPS update endpoint")`.

---

**ID:** S4
**TITLE:** `SCSKILLER_API` environment variable redirects package downloads to an alternate host
**FILE:** src/SCSKiller.Core/App/Updates.cs — `UpdateFeeds.PackageHost` property
**SEVERITY:** Medium
**CATEGORY:** Environment variable trust
**DESCRIPTION:** The `PackageHost` property checks `Environment.GetEnvironmentVariable("SCSKILLER_API")` and if set (non-empty), uses `RouteFailover.Default.Primary` instead of the hardcoded `Packages` URI. The comment says "SCSKILLER_API (a local backend) serves the packages too." This means any process that can set environment variables for the SCSKiller process (e.g., a parent process, a launcher script, or malware running as the user) can redirect package downloads. While the SHA-256 from the signed feed is still checked, this could be used to serve a different binary with the same hash (unlikely) or to track/fingerprint download behavior. More importantly, if `RouteFailover.Default.Primary` is influenced by this variable, the feed fetch itself could be redirected.
**ATTACK SCENARIO:** Malware sets `SCSKILLER_API=http://evil.com` before launching SCSKiller. If `RouteFailover.Default.Primary` picks up this variable, all non-stable feed and package requests go to the attacker's server. The attacker can then serve a malicious feed (which would fail signature verification) or simply block updates. The token is also sent to this server (see S3).
**CONFIDENCE:** Medium (the exact behavior of `RouteFailover` with respect to this variable is not shown)
**RECOMMENDED FIX:** Document that this variable is for development only and strip it from release builds via conditional compilation (`#if DEBUG`). Alternatively, validate that the resulting URI is HTTPS and on an expected domain.

---

**ID:** S5
**TITLE:** `AppStore.GameDir` path traversal check can be bypassed on case-insensitive filesystems with Unicode normalization issues
**FILE:** src/SCSKiller.Core/App/AppStore.cs — `GameDir()` method
**SEVERITY:** Low
**CATEGORY:** Path traversal
**DESCRIPTION:** The `GameDir` method sanitizes game IDs by replacing `:` with `_` and checking `IsPlainName`. For non-plain names, it uses `Segment()` which percent-encodes dangerous characters. The final check uses `Path.GetDirectoryName(Path.GetFullPath(dir))` compared to `Path.GetFullPath(games)` with `StringComparison.OrdinalIgnoreCase`. This is generally robust. However, `Segment()` encodes characters using `%XX` format based on `(int)c`, which for characters above U+00FF would produce `%XXXX` (more than 2 hex digits). `Uri.UnescapeDataString` in `GameId()` may not correctly reverse this for all Unicode ranges, potentially causing inconsistencies. This is more of a correctness issue than a security one, as the path check would still catch traversal.
**ATTACK SCENARIO:** A game ID with specially crafted Unicode characters could potentially create unexpected directory names, though the `GetFullPath` check should catch actual traversal attempts.
**CONFIDENCE:** Low (the path validation appears robust)
**RECOMMENDED FIX:** No immediate action needed. Consider adding explicit rejection of game IDs containing characters above U+007F to simplify the encoding surface.

---

**ID:** S6
**TITLE:** `Busy.Applying` marker file read has a TOCTOU race with the timestamp check
**FILE:** src/SCSKiller.Core/App/Updates.cs — `Busy.Applying()` method
**SEVERITY:** Low
**CATEGORY:** TOCTOU
**DESCRIPTION:** The `Applying` method reads the marker file and checks if the timestamp is within `ApplyingFor` (2 minutes) of the current time. The check is `now - at < ApplyingFor && at - now < ApplyingFor`, which correctly handles both past and future timestamps. The file is opened with `FileShare.ReadWrite | FileShare.Delete`, allowing concurrent access. The TOCTOU window between reading the marker and acting on it is small and the consequence (an update and compile running simultaneously) is a reliability issue, not a security vulnerability.
**ATTACK SCENARIO:** N/A — reliability concern only.
**CONFIDENCE:** Low (as a security issue)
**RECOMMENDED FIX:** N/A for security. The design is sound for its intended purpose.

---

**ID:** S7
**TITLE:** `PathGate` lock file is created in the same directory as the locked file, potentially allowing lock file planting
**FILE:** src/SCSKiller.Core/App/AppStore.cs — `PathGate` constructor
**SEVERITY:** Low
**CATEGORY:** Privilege / File system
**DESCRIPTION:** The `PathGate` creates a lock file at `<path>.lock` with `FileShare.None`. The directory is created if it doesn't exist. If an attacker can create a file at the lock path first (e.g., in a world-writable directory), they could potentially cause a denial of service by holding the lock indefinitely. However, the data directory is `%LOCALAPPDATA%\SCSKiller`, which is per-user and not typically writable by other users. The lock wait timeout (10 minutes default) also mitigates indefinite blocking.
**ATTACK SCENARIO:** Local attacker as the same user plants a lock file to block SCSKiller operations. Limited impact since the attacker already has the same privileges.
**CONFIDENCE:** Low
**RECOMMENDED FIX:** No action needed given the per-user directory model.

---

**ID:** S8
**TITLE:** `Updater.ApplyAsync` deletes all other packages before applying, but `OnlyThis` failure leaves the system in a vulnerable state
**FILE:** src/SCSKiller.App/Updater.cs — `ApplyAsync()` method, `Velo.OnlyThis()` method
**SEVERITY:** Medium
**CATEGORY:** TOCTOU / Update integrity
**DESCRIPTION:** `ApplyAsync` calls `m.OnlyThis(r)` to delete all packages except the target. If this fails (returns false), the update is aborted. However, `OnlyThis` deletes packages one by one, and if a deletion fails partway through, some packages are already deleted. The comment says "Update.exe takes the newest package on disk, whatever it is" if the specific package isn't passed. This means if `OnlyThis` partially fails, Update.exe could pick up an unintended package. The `OnDisk` check verifies the target package's checksum, but if Update.exe falls back to "the newest package on disk," that fallback package's integrity is not verified by SCSKiller (Velopack/Update.exe may verify it, but this is not shown).
**ATTACK SCENARIO:** An attacker who can write to the packages directory places a malicious package with a higher version number. If `OnlyThis` fails to delete it (e.g., due to a file lock), Update.exe may fall back to installing the attacker's package.
**CONFIDENCE:** Medium (depends on Update.exe's fallback behavior, which is Velopack-internal)
**RECOMMENDED FIX:** After `OnlyThis` returns false, explicitly verify that no other packages remain before proceeding. Consider using a dedicated, empty staging directory for the target package rather than the shared packages directory.

---

**ID:** S9
**TITLE:** `SignedFeedSource.GetReleaseFeed` merges feeds from multiple channels without cross-channel version conflict detection
**FILE:** src/SCSKiller.App/Updater.cs — `SignedFeedSource.GetReleaseFeed()` method
**SEVERITY:** Low
**CATEGORY:** Insufficient validation
**DESCRIPTION:** The method merges assets from the channel's feed and later channels' feeds. The deduplication is by `FileName` only (`have.Contains(a.FileName)`). Two different channels could list the same filename with different content (different SHA-256). The first one encountered wins. Since feeds are processed in order (chosen channel first, then later channels), the chosen channel's version takes precedence. This is correct behavior. However, if a later channel's feed lists a package with the same filename but different hash, it is silently dropped. This is not a vulnerability but could mask feed inconsistencies.
**ATTACK SCENARIO:** N/A — the deduplication logic is correct for the stated design.
**CONFIDENCE:** Low (not a vulnerability)
**RECOMMENDED FIX:** N/A

---

**ID:** S10
**TITLE:** `FeedTrust.Verify` does not validate `signed_at` freshness (accepts arbitrarily old or future-dated signatures)
**FILE:** src/SCSKiller.Core/App/Updates.cs — `FeedTrust.Verify()` method
**SEVERITY:** Medium
**CATEGORY:** Weak crypto / Replay
**DESCRIPTION:** The `Verify` method validates the Ed25519 signature and SHA-256 hash but performs no freshness check on `signed_at`. It parses the timestamp but only uses it for the replay check in `Accept()` (comparing to previously seen). A feed signed with a `signed_at` of "1970-01-01" or "2099-12-31" would pass `Verify`. The `Accept` method's replay check (`at < seen`) only prevents going backward, not forward. This means:
1. A very old feed (if the attacker has an old valid signature) could be presented on first run (no `seen` value exists yet).
2. A future-dated feed blocks all subsequent updates (as described in S2).
**ATTACK SCENARIO:** On a fresh install (no `feeds.json`), an attacker who has intercepted an old signed feed can replay it. Since there's no `seen` value, the old feed is accepted. The attacker can then serve an old (vulnerable) version as the "latest" update.
**CONFIDENCE:** Medium (requires old signed feed interception, but the threat model includes network attackers)
**RECOMMENDED FIX:** In `Verify` or `Accept`, reject feeds where `signed_at` is more than N days in the past (e.g., 30 days) or more than 1 hour in the future. This limits the replay window and the future-dating attack.

---

## UNVERIFIED OBSERVATIONS

1. **RouteFailover implementation** — The `RouteFailover.Default` property and its `Primary` URI are referenced but not supplied. This class is critical for understanding where non-stable feeds and packages are fetched from, whether TLS is enforced, and whether the `SCSKILLER_API` environment variable influences it. **Needed file:** `src/SCSKiller.Core/App/RouteFailover.cs` (or wherever `RouteFailover` is defined).

2. **Velopack's Update.exe fallback behavior** — The comment in `Updater.cs` states "Update.exe takes the newest package on disk, whatever it is" when the specific package isn't passed. The security of this fallback depends on whether Update.exe independently verifies package signatures/checksums. **Needed file:** Velopack's Update.exe source or documentation.

3. **Account token acquisition** — `App.Account.GetAccessTokenAsync()` is called but not shown. The token's scope, lifetime, and storage mechanism are unknown. **Needed file:** Account/authentication module.

4. **Native C++ component and proxy DLL** — The threat model mentions a C++ native component and a Vulkan/D3D proxy DLL (`d3d12.dll`) loaded into game processes. None of these files were supplied. Memory safety in the proxy DLL is flagged as "especially severe" in the threat model but cannot be assessed. **Needed files:** All C++ source files, especially the proxy DLL's entry points, shader parsing, and IPC handling.

5. **Shader container/cache parsing** — The threat model mentions parsing untrusted shader containers from games. No parsing code was supplied. **Needed files:** Any files related to shader parsing, plan.bin reading, or cache file handling.

6. **`Settings` class and `InstallUpdatesAutomatically` default** — The `AppStore.DefaultSettings` property sets defaults but the `Settings` class definition is not shown. Whether auto-install is on by default affects the attack surface. **Needed file:** Settings class definition.

7. **`KeyFiles.Prune` and `KeyFiles.Forget`** — These methods are called but not shown. They manage key files in game directories and could have path traversal or race condition issues. **Needed file:** KeyFiles class.

---

## SUMMARY

| ID | Title | Severity | Confidence |
|----|-------|----------|------------|
| S1 | Ed25519 keys hardcoded, no rotation | High | High |
| S2 | Future-dated feed blocks updates | Medium | High |
| S3 | Bearer token sent without HTTPS check | Medium | Medium |
| S4 | SCSKILLER_API env var redirects downloads | Medium | Medium |
| S8 | Partial package deletion before update | Medium | Medium |
| S10 | No signed_at freshness validation | Medium | Medium |
| S5 | Unicode edge case in path encoding | Low | Low |
| S6 | Busy marker TOCTOU | Low | Low |
| S7 | Lock file planting | Low | Low |

The update system's signature verification (Ed25519 with pinned keys, SHA-256 hash checking) is fundamentally sound. The most significant risks are the lack of key rotation (S1), the missing freshness check on `signed_at` (S10, S2), and the potential for token leakage via the `SCSKILLER_API` environment variable and `RouteFailover` (S3, S4). The critical attack surface — the native proxy DLL injected into game processes — could not be assessed as no C++ files were supplied.

## CHUNK 1

# Security Audit Report: SCSKiller v1.2.5

## Summary

This audit examines the supplied source files for concrete, exploitable vulnerabilities. The threat model includes local attackers controlling game files, network responses, and the update feed. The proxy DLL (`d3d12.dll`) runs inside game processes, making memory-safety bugs there critical.

---

## Findings

### S1: Unbounded Memory Allocation from Untrusted File Content

**FILE**: `src/SCSKiller.Core/Carved/CarvedReader.cs` — `Carve()` method, `ReadAt()` method

**SEVERITY**: High

**CATEGORY**: Memory corruption / Resource exhaustion

**DESCRIPTION**: 
The `Carve()` method reads container sizes from file content (`Dxbc.HeaderSize(hd)`) and uses this to allocate memory via `ReadAt()`. The size value comes directly from attacker-controlled file bytes:

```csharp
var size = Dxbc.HeaderSize(hd);
if (size == 0 || off + size > len) continue;
ReadOnlySpan<byte> c = at + size <= n ? span.Slice(at, size) : ReadAt(h, off, size);
```

`ReadAt()` allocates `new byte[size]` where `size` is derived from the file. While there is a bounds check (`off + size > len`), a malicious file can declare a container size up to the file's length. A multi-GB shader file could cause allocation of multi-GB buffers per container.

The `MaxBytes` constant (128 MB) limits individual file reads in `ReShade.Find()`, but `CarvedReader` has no equivalent per-container limit—only the file size bounds it.

**ATTACK SCENARIO**:
1. Attacker crafts a game shader file with a fake DXBC header declaring a 4GB container size
2. SCSKiller's `Index()` or `Detect()` processes this file
3. `ReadAt()` attempts to allocate 4GB
4. Repeated across multiple fake containers, this exhausts memory (DoS) or causes GC pressure

**CONFIDENCE**: High — the code path is clear and the size comes from untrusted input.

**RECOMMENDED FIX**:
Add a maximum container size check before allocation:
```csharp
const int MaxContainerSize = 64 << 20; // 64 MB reasonable max for a shader
if (size == 0 || size > MaxContainerSize || off + size > len) continue;
```

---

### S2: Path Traversal in ReShade AddonPath Resolution

**FILE**: `src/SCSKiller.Core/Games/ReShade.cs` — `At()` method, `Config()` method

**SEVERITY**: Medium

**CATEGORY**: Path traversal

**DESCRIPTION**:
`Config()` reads `AddonPath` from ReShade.ini without validating it stays within the expected directory:

```csharp
if (key.Equals("AddonPath", StringComparison.OrdinalIgnoreCase) && value.Trim('"') is { Length: > 0 } p) 
    addonPath = p;
```

Then in `At()`:
```csharp
var addonDir = addonPath != null ? GameFiles.DirKey(Path.Combine(dir, addonPath)) : dir;
```

While `DirKey` normalizes the path, there's no check that `addonDir` remains within `dir` or the game's install folder. An absolute path or `..\..\..\` traversal in `AddonPath` causes SCSKiller to enumerate and classify `.addon`/`.addon64` files from arbitrary directories.

The subsequent `Stage()` method copies these files:
```csharp
foreach (var a in r.Addons.Where(a => a is { Disabled: false, Kind: not AddonKind.NotPipeline })) 
    File.Copy(a.Path, Path.Combine(dest, Path.GetFileName(a.Path)));
```

**ATTACK SCENARIO**:
1. Attacker controls a game's ReShade.ini (ships with the game or modifiable)
2. Sets `AddonPath = C:\Windows\System32` or `AddonPath = ..\..\..\Sensitive`
3. SCSKiller scans that directory for `.addon` files
4. If any exist (or attacker places them), they're copied to the staging directory and potentially loaded by the warm process

**CONFIDENCE**: Medium — requires specific ReShade configuration but the traversal is real.

**RECOMMENDED FIX**:
Validate `addonPath` stays within the expected directory:
```csharp
var addonDir = addonPath != null ? Inside(dir, addonPath) : null;
if (addonDir == null) addonDir = dir; // fallback to safe default
```
Use the existing `Inside()` helper that validates containment.

---

### S3: DLL Search Order Vulnerability in StreamlineFirst Check

**FILE**: `src/SCSKiller.Core/Games/GameFiles.cs` — `StreamlineFirst()` method

**SEVERITY**: Medium

**CATEGORY**: DLL hijacking / Unchecked native input

**DESCRIPTION**:
`StreamlineFirst()` determines if Streamline's interposer loads before d3d12.dll. It checks imports recursively but trusts the exe's directory contents:

```csharp
var local = Path.Combine(dir, dll);
files.Add(local);
if (File.Exists(local)) todo.Push((local, true));
```

The method doesn't verify the authenticity or signature of DLLs it finds. An attacker who can write to the game directory can place a malicious DLL that:
1. Exports forwarders to d3d12 (making `StreamlineFirst` return false, changing behavior)
2. Gets loaded by the actual game before SCSKiller's proxy

While SCSKiller doesn't directly load these DLLs, the decision logic affects whether the proxy is installed, potentially causing the proxy to be skipped when it should be used, or vice versa.

**ATTACK SCENARIO**:
1. Attacker places a crafted `sl.interposer.dll` or dependency DLL in the game folder
2. SCSKiller's detection logic makes incorrect assumptions about load order
3. Proxy DLL is either not installed when needed, or the attacker's DLL loads first in the actual game

**CONFIDENCE**: Medium — this is more about incorrect security decisions than direct exploitation.

**RECOMMENDED FIX**:
Document that this is a heuristic only. For security-critical decisions, verify file signatures or use absolute paths to known-system DLLs.

---

### S4: Regex Denial of Service in Log Parsing

**FILE**: `src/SCSKiller.Core/Games/ReShade.cs` — `LogVerdicts()` method, regex definitions

**SEVERITY**: Low

**CATEGORY**: Regex DoS

**DESCRIPTION**:
The regex patterns used to parse ReShade.log:

```csharp
static readonly Regex Loading = new(@"Loading add-on from '(.+)' \.\.\.$");
static readonly Regex Registered = new(@"Registered add-on ""(.+?)""");
static readonly Regex Pipeline = new(@"\| \[(.+?)\] mods::shader::(OnCreatePipelineLayout\(will insert|OnInitPipelineLayout\(Cloning)");
```

The `.+` and `.+?` patterns can cause catastrophic backtracking on crafted input. While `Registered` uses lazy matching (`.+?`), `Loading` uses greedy `.+` which can backtrack significantly.

ReShade.log is written by the game process, which an attacker controls if they've compromised the game or can influence its ReShade installation.

**ATTACK SCENARIO**:
1. Attacker causes ReShade.log to contain lines like `Loading add-on from 'aaaa...aaaa' ...` with thousands of characters
2. SCSKiller parses the log during detection
3. Regex matching consumes excessive CPU

**CONFIDENCE**: Low — ReShade.log format is somewhat constrained, and .NET regex has some protections.

**RECOMMENDED FIX**:
Add length limits before regex matching:
```csharp
if (line.Length > 4096) continue; // reasonable max for a log line
```

---

### S5: Cached File Content Trust (TOCTOU)

**FILE**: `src/SCSKiller.Core/Games/ReShade.cs` — `Cached()` method

**SEVERITY**: Low

**CATEGORY**: TOCTOU

**DESCRIPTION**:
The `Cached()` method checks file size and write time to validate cache freshness:

```csharp
if (Probed.TryGetValue(key, out var c) && (c.Length, c.Written, c.Identity) == (f.Length, f.LastWriteTimeUtc, identity)) 
    return c.Value;
```

However, `Identity` is obtained via `KeyFiles.Identity()` which reads file attributes. Between the cache check and the actual use of cached data, the file could be replaced. The `Identity` check (file ID) mitigates this somewhat, but:

1. The identity check happens at cache lookup time
2. The cached value is returned and used later
3. An attacker with write access could replace the file after the check

**ATTACK SCENARIO**:
1. Attacker has write access to game files
2. SCSKiller caches a benign file's classification
3. Attacker replaces the file with a malicious version
4. SCSKiller uses stale cached classification for the new file

**CONFIDENCE**: Low — requires precise timing and the file ID check provides some protection.

**RECOMMENDED FIX**:
For security-critical decisions, re-read file content rather than trusting cache. Document that caching is for performance, not security.

---

### S6: Unvalidated JSON Parsing in Shader-Mods Table

**FILE**: `src/SCSKiller.Core/Games/ReShade.cs` — `ParseTable()` method

**SEVERITY**: Low

**CATEGORY**: Insecure deserialization

**DESCRIPTION**:
```csharp
static Dictionary<string, AddonKind> ParseTable(string json)
{
    using var doc = JsonDocument.Parse(json);
    var table = new Dictionary<string, AddonKind>(StringComparer.OrdinalIgnoreCase);
    foreach (var (key, kind) in new[] { ("layout_injecting", AddonKind.LayoutInjecting), ("replaces_shaders", AddonKind.ReplacesShaders) })
        foreach (var e in doc.RootElement.GetProperty(key).EnumerateArray()) 
            table[e.GetString()!] = kind;
    return table;
}
```

The JSON comes from `ContentFile.Embedded()`, suggesting it's an embedded resource. If this is truly embedded at compile time, it's not attacker-controlled. However, if the resource can be replaced or comes from an external source:

1. No validation of string values
2. No size limits on the JSON
3. `GetString()!` assumes non-null

**ATTACK SCENARIO**:
If the embedded resource can be replaced (e.g., via DLL hijacking of the assembly containing it), attacker controls the shader mod classification table.

**CONFIDENCE**: Low — embedded resources are typically signed with the assembly.

**RECOMMENDED FIX**:
Verify the resource is truly embedded and signed. Add input validation even for trusted sources.

---

## Unverified Observations

### O1: Proxy DLL Memory Safety
**Observation**: The prompt mentions a C++ native component and Vulkan/D3D proxy DLL (`d3d12.dll`), but no source for these was provided. Memory-safety bugs in the proxy would be critical as it runs inside game processes.

**Needed to confirm**: Source code for `proxy.cpp` or equivalent native files.

### O2: Update Mechanism Security
**Observation**: The threat model mentions "the update feed / its signature" but no update-related code was provided. The `AppStore.WriteAtomic()` call in `SaveProbes()` suggests file writing utilities exist, but update validation is unknown.

**Needed to confirm**: Update checking and installation code, signature verification logic.

### O3: Network Communication
**Observation**: `api.scskiller.com` is mentioned in the threat model but no network code was provided. TLS validation, certificate pinning, and response handling are unknown.

**Needed to confirm**: HTTP client code, API communication layer.

### O4: Injection Mechanism
**Observation**: How SCSKiller injects into game processes is not shown. Process hollowing, DLL injection, or other techniques have different security implications.

**Needed to confirm**: Injection code, process creation/manipulation logic.

### O5: KeyFiles.Identity Implementation
**Observation**: `KeyFiles.Identity()` is called in `Cached()` but its implementation isn't shown. If it doesn't actually read file content or use secure identification, the TOCTOU protection may be weaker than assumed.

**Needed to confirm**: `KeyFiles` class implementation.

### O6: ShaderContainer.Parse Safety
**Observation**: `ShaderContainer.Parse()` is called with carved container data but its implementation isn't shown. Parsing binary shader formats is a common source of memory corruption bugs.

**Needed to confirm**: `ShaderContainer` class, `Dxbc` struct implementations.

---

## Prioritized Recommendations

1. **Immediate**: Add container size limits in `CarvedReader.Carve()` (S1)
2. **High**: Validate `AddonPath` containment in ReShade handling (S2)
3. **Medium**: Review DLL trust decisions in `StreamlineFirst()` (S3)
4. **Low**: Add regex input limits (S4), document caching assumptions (S5)

The most critical finding is **S1** — unbounded allocation from untrusted file content. This is directly exploitable for DoS and potentially for memory corruption if integer overflows occur in size calculations.

## CHUNK 2

# SECURITY AUDIT — SCSKiller v1.2.5 (supplied files only)

Scope note: only two files were supplied (`ScsKiller.Offline.cs`, `Program.cs`). Several critical subsystems referenced by the threat model (update feed verification, shader container parsing, the native proxy DLL, vendor API client) are **not** in the supplied code. Findings below are limited to what I can demonstrate from these two files; everything else is listed under Unverified Observations.

---

## FINDINGS

### S1 — Arbitrary command execution via `OfflineArguments` passed unsanitized to `CreateProcessW`

- **ID:** S1
- **TITLE:** Command-line injection into game process launch
- **FILE + LOCATION:** `src/SCSKiller.Core/App/ScsKiller.Offline.cs` — `StartAttested()` (`var cmd = new StringBuilder($"\"{exe}\"" + (args.Length > 0 ? " " + args : ""));`), fed by the settable property `internal string OfflineArguments { get; set; }` and consumed in `StartOffline()` → `StartAttested(g.ExePath, OfflineArguments, ...)`
- **SEVERITY:** High
- **CATEGORY:** Command injection (Win32 command-line parsing)
- **DESCRIPTION:** `StartAttested` builds the `lpCommandLine` for `CreateProcessW` by naive string concatenation: `"\"{exe}\" " + args`. `args` is `OfflineArguments`, a public settable property with no validation. Win32 command lines are parsed by the *child* process (`CommandLineToArgvW`), and quoting is not escaped here. If `OfflineArguments` can be influenced by anything other than the local interactive user (a config file, a future IPC surface, a game-supplied field, a CLI flag), an attacker can inject arbitrary arguments into a process SCSKiller launches. More subtly, `exe` itself is embedded in the quoted string without escaping; if `g.ExePath` ever contained a `"` (possible on NTFS via short names or crafted junctions is unlikely, but the pattern is unsafe), the quoting breaks. The concrete risk today is argument injection: e.g., for a game whose launcher binary re-parses arguments and supports `--load-module <path>` / URL-handler style flags, injected args cause code execution in the launched (attested) process context — a process SCSKiller has just armed the recorder for and treats as trusted.
- **ATTACK SCENARIO:** Attacker controls or influences the value of `OfflineArguments` (e.g., via a per-game settings file or a game manifest field that a future/other code path copies into it — the property is `internal` but settable from anywhere in the assembly, and the supplied code shows no provenance check). SCSKiller starts the game suspended, arms attestation for exactly that PID, then resumes it with attacker-chosen arguments. The injected arguments execute in a process the tool explicitly trusts.
- **CONFIDENCE:** Medium — the sink (`CreateProcessW` with concatenated, unescaped args) is confirmed in the supplied code; the *source* of `OfflineArguments` is not shown (it defaults to `""` and is marked "(tests)"). If it is only ever set by tests, severity drops to informational. The pattern itself is unsafe regardless.
- **RECOMMENDED FIX:** Treat the argument string as untrusted: (1) if it is genuinely test-only, remove it from production builds (`#if DEBUG`) or make it `internal` + `[Conditional]`; (2) if it is a real feature, build the command line with proper quoting/escaping (`\"` → `\\"` per `CommandLineToArgvW` rules) and validate against an allowlist of permitted flags; (3) never concatenate `exe` into the quoted portion without escaping embedded quotes — pass it as `lpApplicationName` (already done) and use a minimal, fixed `lpCommandLine`.

---

### S2 — PID reuse check relies on creation-time equality, but `EndSuspended`/`Alive` trust a 5-second wait and a non-atomic check

- **ID:** S2
- **TITLE:** TOCTOU between process-identity check and `TerminateProcess`/`WaitForSingleObject` on the offline session PID
- **FILE + LOCATION:** `ScsKiller.Offline.cs` — `Alive()`, `EndSuspended()`, and the cleanup loop in `RunOfflineCleanup()`
- **SEVERITY:** Medium
- **CATEGORY:** TOCTOU / PID reuse
- **DESCRIPTION:** The code mitigates classic PID reuse by comparing `GetProcessTimes` creation time against the recorded `Started` value before acting (`Alive`, `EndSuspended`, and the helper's wait loop all do this). That is good. However: (a) in `EndSuspended`, the sequence is `OpenProcess(Terminate|Synchronize)` → check creation time → `TerminateProcess` → `WaitForSingleObject(h, 5000)`. The handle is opened *before* the time check, so the handle itself pins the correct process — this part is actually safe. (b) In `RunOfflineCleanup`, the wait path `WaitForSingleObject(h, uint.MaxValue)` for a resumed session is also handle-bound and safe. (c) The residual issue: `Alive()` opens with `QueryLimitedInformation|Synchronize` and returns a boolean; callers (`OfflineLive`, `CleanOfflineSession`) then act on the *record* (`s.Pid`) rather than the handle. Between `Alive()` returning false (process exited) and `CleanOfflineSession` proceeding to delete files, a new process can be started from the same directory — but file deletion is name- and hash-gated (`Ours()`), so impact is limited. The one genuinely sharp edge: `EndSuspended` waits only 5 s for termination and returns the boolean result of the wait, but `CleanOfflineSession` treats `!EndSuspended(s)` as "still alive, leave files" — correct — while treating success as license to delete. If `TerminateProcess` succeeded but the process is a *different* process that coincidentally matched pid+creation time (practically impossible), files would be deleted while it runs. This is theoretical.
- **ATTACK SCENARIO:** Local attacker with the ability to start processes in the game folder races SCSKiller's cleanup: after `Alive()` reports the session dead, attacker starts a process from the game directory before `CleanOfflineSession` finishes deleting journaled files. Because deletion is gated by `Ours()` (name prefix `scskiller`, `.scskiller-new` suffix, or SHA-256 match against the recorded hash), the attacker cannot get *their* file deleted — but they can keep a stale `d3d12.dll` proxy alive by replacing it with a non-matching file, forcing the journal to retain entries and the RunOnce persistence to remain.
- **CONFIDENCE:** Low as an exploitable vulnerability; the design (handle-bound checks + hash-gated deletion) is largely sound. Reported as Medium→Low hardening note rather than a confirmed exploit.
- **RECOMMENDED FIX:** Keep the handle from `Alive()` and pass it through to the deletion phase so the entire check-and-act sequence is handle-bound; document that `Ours()` hash-gating is the real mitigation and ensure `Sha256(path)` reads the file with `FileShare.None` to prevent an attacker swapping content mid-hash.

---

### S3 — `RunOnce` registry persistence value name embeds unsanitized `gameId`

- **ID:** S3
- **TITLE:** Registry value-name injection via `gameId` in RunOnce persistence
- **FILE + LOCATION:** `ScsKiller.Offline.cs` — `RunOnceEntry()` (`$"!SCSKiller offline cleanup {gameId}"`) and `HelperMutex()` (`@"Local\SCSKiller-offline-cleanup-" + gameId.Replace('\\', '_')`)
- **SEVERITY:** Low
- **CATEGORY:** Privilege / persistence hygiene (registry value-name injection)
- **DESCRIPTION:** `gameId` is interpolated directly into a HKCU RunOnce value *name* and a mutex name. The mutex path replaces only `\`; the registry name replaces nothing. `gameId` values come from `AppStore.GameId(Path.GetFileName(d))` over directories in the data folder and from game records — i.e., partially derived from filesystem names that a local attacker (or a malicious game install that SCSKiller scans) could influence. A `gameId` containing characters valid in a registry value name but unexpected (very long string, leading `!`, control characters) could: collide with the `!` prefix semantics (RunOnce treats leading `!` as "delete after run"), create duplicate/conflicting persistence entries, or create mutex-name collisions between two different game IDs (`a/b` and `a_b` map to the same mutex after the `\`→`_` replace). Mutex collision means one game's cleanup helper blocks another's update gate (`HelperRuns`) — a cross-game denial of service, and potentially a cleanup that never runs because the wrong helper holds the mutex.
- **ATTACK SCENARIO:** Attacker arranges for two game IDs that differ only by a path separator vs. underscore (e.g., via a crafted game install directory name that the scanner turns into an ID). Both map to `Local\SCSKiller-offline-cleanup-a_b`. While game A's cleanup helper runs, game B's `OfflineBlocksUpdate` returns true and vice versa; worse, `CleanOfflineSession` for B may be skipped because the mutex check is per-name, letting B's proxy `d3d12.dll` persist in a game folder across an update that assumed cleanup had run.
- **CONFIDENCE:** Medium on the collision mechanic (the `Replace('\\','_')` collision is deterministic); Low on real-world impact since game ID generation isn't fully shown.
- **RECOMMENDED FIX:** Sanitize `gameId` before using it in mutex/registry names (allowlist `[A-Za-z0-9_.-]`, hash the rest), and make the mapping injective (e.g., `Local\SCSKiller-offline-cleanup-` + SHA256(gameId)[..16]). Apply the same sanitization to the RunOnce value name.

---

### S4 — `CleanOfflineSession` deletes files by name under a prefix/suffix rule without ownership proof

- **ID:** S4
- **TITLE:** `Ours()` returns `true` for any `scskiller*` or `*.scskiller-new` file regardless of origin
- **FILE + LOCATION:** `ScsKiller.Offline.cs` — local function `Ours(string file)` inside `CleanOfflineSession`: `if (file.StartsWith("scskiller", StringComparison.OrdinalIgnoreCase) || file.EndsWith(TempSuffix, StringComparison.OrdinalIgnoreCase)) return true;`
- **SEVERITY:** Medium
- **CATEGORY:** Insecure file deletion / local DoS (limited)
- **DESCRIPTION:** The cleanup's ownership test short-circuits to `true` for any file whose name starts with `scskiller` or ends with `.scskiller-new`, without hashing or signature checks. Those files are then `File.Delete`d if their names are in the session's `Created` journal — and `Created` includes `RecorderDataFiles`, `Recordings.AppFiles`, and temp variants, i.e., names like `scskiller.db`, `scskiller.ini`, `scskiller.log` (exact set not shown). A local attacker who can write into the game directory can plant a *decoy* `scskiller.db` (or drop a hard link / junction at that name pointing at a file the attacker wants deleted). `File.Delete` on a junction/hard link deletes the link, not the target, on NTFS — so this is not an arbitrary-file-deletion primitive. The realistic impact is: (a) attacker plants a malicious `scskiller.db` that cleanup then *merges* via `Recordings.Merge(recording, inbox.FullName, null)` — the merge path parses attacker-controlled bytes (see S5); (b) attacker keeps cleanup looping forever by recreating journaled names, preserving the RunOnce persistence and blocking updates (`OfflineBlocksUpdate`). Deletion itself is confined to SCSKiller's own filenames, so the direct damage is bounded.
- **ATTACK SCENARIO:** Local attacker (or a malicious game) drops a crafted `scskiller.db` into the game folder while a session is pending. On cleanup, SCSKiller merges it into the trusted `recording.db` in its data folder (`Recordings.Merge`), importing attacker-controlled pipeline records that later feed compile planning. Separately, repeatedly recreating journaled filenames keeps `OfflineBlocksUpdate` true indefinitely (update DoS).
- **CONFIDENCE:** Medium — the prefix-true rule and the merge call are confirmed in the supplied code; the parser robustness of `Recordings.Merge` is not shown (see S5 / Unverified).
- **RECOMMENDED FIX:** Extend the hash-gated branch to *all* journaled names: record expected SHA-256 for every file the session creates (the code already does this for `d3d12.dll`, `scskiller.ini`, `steam_appid.txt` via `rec.RecorderFiles`) and require a hash match before deleting *or merging* `scskiller.db`. Never merge a recording inbox whose hash wasn't recorded at session start.

---

### S5 — Attacker-controlled `scskiller.db` merged into trusted recording store with only `InvalidDataException` as the guard

- **ID:** S5
- **TITLE:** Untrusted recording database ingested by `Recordings.Merge`
- **FILE + LOCATION:** `ScsKiller.Offline.cs` — `CleanOfflineSession`, block `if (!others && s.Created.Contains("scskiller.db") && inbox is { Exists: true, Length: > 0 }) … Recordings.Merge(recording, inbox.FullName, null);`
- **SEVERITY:** High (pending parser confirmation)
- **CATEGORY:** Unchecked native input / insecure deserialization (format parser)
- **DESCRIPTION:** The offline-session recording inbox (`scskiller.db` in the game folder) is written by the proxy DLL *inside the game process* — a process the threat model explicitly treats as attacker-influenceable. Cleanup merges that file into SCSKiller's trusted `recording.db` with no authenticity check: no MAC, no signature, no hash recorded at session start (contrast with `d3d12.dll`, which *is* hash-recorded in `rec.RecorderFiles`). The only safety net is that `Recordings.Merge` throws `InvalidDataException` on malformed input, which is caught. Whatever records survive parsing become trusted compile-plan inputs (`recording.db` is later read by `PsoDb.Read` in `ReferenceExport` and by compile planning). If the db format embeds lengths/offsets consumed by the C++ component or by unsafe parsing anywhere downstream, this is a memory-corruption or at minimum a trusted-data-poisoning vector (e.g., inject bogus pipeline records that cause the compiler to process attacker-chosen shader bytes — and shader bytes from untrusted games are explicitly in scope per the threat model).
- **ATTACK SCENARIO:** Attacker controls the game process (threat model item c) or can write the game directory. They craft `scskiller.db` with malicious records. SCSKiller's cleanup merges it into `%data%\games\<id>\recording.db`. Later compiles consume those records; if any length field reaches the native compiler/warmer unchecked, memory corruption in an elevated or user-context process results; at minimum the compile plan is poisoned.
- **CONFIDENCE:** Medium — ingestion without authenticity is confirmed; exploitability depends on the `Recordings.Merge`/`PsoDb` parser (not supplied). Listed as High severity, Medium confidence.
- **RECOMMENDED FIX:** At session start, record the expected properties of the inbox (or better: have the proxy DLL HMAC its output with a per-session key SCSKiller generates and stores in `scskiller.ini`, which *is* hash-protected). Verify before merge. Failing that, treat merged records as untrusted: strict bounds-checked parsing, reject records whose shader bytes don't match known content hashes, and never let lengths from the db size native allocations without caps.

---

### S6 — `fetch-codecs` / `Codecs.Ensure` downloads native DLLs with no visible signature verification in the call path

- **ID:** S6
- **TITLE:** Codec DLL download path — verification not shown at call site
- **FILE + LOCATION:** `src/SCSKiller.Cli/Program.cs` — `FetchCodecs()` → `Codecs.Ensure(OodleHelper.OodleFileName, Codecs.DownloadOodle, dir)` and `Codecs.Ensure(ZlibHelper.DllName, p => ZlibHelper.DownloadDll(p, null!), dir)`
- **SEVERITY:** Critical if unverified; otherwise not a finding
- **CATEGORY:** Supply chain / missing signature verification
- **DESCRIPTION:** The CLI downloads Oodle and zlib native DLLs and places them next to the executables, where they "seed each user's codecs folder" — i.e., these DLLs will be loaded into SCSKiller and possibly into game processes. The supplied code shows only that `InvalidDataException` from the download helpers is treated as failure, which *suggests* a hash check inside `DownloadOodle`/`DownloadDll` (the comment says "pinned"), but no pin value, signature check, or TLS requirement is visible in the supplied files. The threat model explicitly requires validating signatures/hashes on anything downloaded and executed. If the pin is a hardcoded SHA-256 checked before placement, this is fine; if it relies on TLS alone or a hash fetched from the same origin, it is Critical.
- **ATTACK SCENARIO:** Attacker controls network responses (threat model item d) or compromises the codec distribution endpoint. They serve a trojaned `oo2core_*.dll`. If verification is absent or the expected hash is fetched from the same compromised origin, SCSKiller places the DLL next to its exe and loads it — code execution in the app and potentially in every game the proxy chains into.
- **CONFIDENCE:** Low that it's unmitigated (the "pinned" comment and `InvalidDataException` catch imply a check); the check itself is **not in the supplied code**, so this is reported as a finding requiring confirmation rather than dismissed.
- **RECOMMENDED FIX:** Hardcode the expected SHA-256 (and Authenticode publisher) of each codec DLL in the source; verify bytes before `File.Move` into place; fail closed. Show the verification in the same file as the download for auditability.

---

### S7 — Elevated result file path (`--result`) and `--for-user` handling allow result-file planting to arbitrary path

- **ID:** S7
- **TITLE:** Elevated CLI writes result JSON to an attacker-chosen path
- **FILE + LOCATION:** `Program.cs` — top-level: `resultFile = Opt(Elevated.ResultArg); … if (resultFile != null) Elevated.WriteResult(resultFile, code == 0, Outcome.Message ?? "");`
- **SEVERITY:** Medium
- **CATEGORY:** Privilege (elevated file write)
- **DESCRIPTION:** When run elevated (the app launches the CLI via `runas` for `cache set` / `nvidia-auto-shader`), the process writes a result file to whatever path `--result <file>` specifies. The path is taken from the command line with no validation (no check that it is under a temp dir, no check for reparse points). If a non-admin local attacker can influence the arguments the *app* passes to the elevated CLI — or can pre-create the result path as a junction/hard link — the elevated process will create/overwrite a file at an attacker-chosen location. `Elevated.WriteResult` implementation is not shown; if it uses `File.WriteAllText` on a pre-existing hard link, it writes through to the link target with admin privileges (classic elevated-file-write primitive). The `--for-user <SID>` check (`sid != Elevated.CurrentUserSid` → refuse) shows awareness of over-the-shoulder UAC, but nothing guards the result path itself.
- **ATTACK SCENARIO:** Attacker (standard user) predicts or influences the `--result` path used by the app's elevated invocation, pre-creates it as a hard link to `C:\Windows\System32\<target>`. Elevated CLI writes JSON through the link → arbitrary file overwrite as admin. Even without hard links, if the app constructs the result path from user-writable input, the attacker redirects the write.
- **CONFIDENCE:** Medium — the unvalidated path from CLI arg to elevated write is confirmed; whether `WriteResult` is vulnerable to link-following is not shown.
- **RECOMMENDED FIX:** Generate the result path in the *app* under `%ProgramData%\SCSKiller` with a random name and ACL it to admins+SYSTEM before elevation; in the CLI, canonicalize the path, refuse junctions/symlinks (`File.ResolveLinkTarget` / `FILE_FLAG_OPEN_REPARSE_POINT` check), and open with `FileMode.CreateNew` (fail if exists) or verify the file was created by this process.

---

### S8 — `Confirm()` reads the confirmation answer from stdin when redirected, enabling piped-consent bypass of interactive prompts

- **ID:** S8
- **TITLE:** Piped stdin auto-confirms destructive/elevated operations
- **FILE + LOCATION:** `Program.cs` — `Confirm()`: `var piped = Console.IsInputRedirected; var answer = piped ? Elevated.ReadAnswer(Console.OpenStandardInput()) : Console.ReadLine()?.Trim();`
- **SEVERITY:** Low
- **CATEGORY:** Auth/consent UX bypass
- **DESCRIPTION:** Destructive operations (`cache clear`, `record clear`) and global driver changes (`cache set`, `nvidia-auto-shader`) gate on an interactive `y`. When stdin is redirected, the answer is read from the pipe — meaning any process/script that can invoke the CLI with a pipe can supply `y` non-interactively. The usage text even documents "pipe y to confirm". For the elevated commands there is a `--yes` escape hatch anyway, so this adds little new exposure *for those commands*; but for `cache clear --game-precache` (deletes the game's own caches) and `record clear`, a local process running as the user can silently destroy data by piping `y`. This is a consent-UX weakness, not a privilege boundary crossing (the attacker is already the user), hence Low.
- **ATTACK SCENARIO:** Malware running as the user executes `echo y | scskiller cache clear <game> --game-precache` to destroy shader caches / recordings (sabotage, anti-forensics against the tool's records).
- **CONFIDENCE:** High (behavior is explicit in code and usage text).
- **RECOMMENDED FIX:** Require `--yes` for non-interactive confirmation (fail when `IsInputRedirected` unless `--yes` is present), so silent consent requires an explicit flag that appears in logs/command lines.

---

### S9 — `Busy.Applying` gate can be bypassed by invoking `fetch-codecs`, which skips the update-exclusion check

- **ID:** S9
- **TITLE:** `fetch-codecs` exempt from update-in-progress exclusion
- **FILE + LOCATION:** `Program.cs` — `if (args[0] != "fetch-codecs" && Busy.Applying(...))`
- **SEVERITY:** Low
- **CATEGORY:** TOCTOU / update safety
- **DESCRIPTION:** Every command except `fetch-codecs` refuses to run while an update is being applied ("Update.exe replaces this folder"). The exemption is deliberate (packaging), but `fetch-codecs` *writes DLLs next to the executables* — precisely the files an update replaces. If a local attacker can trigger `fetch-codecs` concurrently with an update apply (both are user-context), they can race file replacement: e.g., plant a codec DLL in the window between the updater's hash check and its move, or keep a stale/malicious DLL in place that survives the update. Impact is bounded by S6's verification (if pinned-hash verification exists, the planted DLL is rejected) — which is why this is Low and coupled to S6.
- **ATTACK SCENARIO:** Attacker times `scskiller fetch-codecs <dir>` against the updater to write into the install folder mid-apply, aiming to leave a non-updated or attacker-supplied DLL after the update completes.
- **CONFIDENCE:** Low-Medium (depends on updater internals and S6's verification, neither supplied).
- **RECOMMENDED FIX:** Apply the `Busy.Applying` gate to `fetch-codecs` as well when the target dir is the live install dir; only exempt it when `--out`/dir is a packaging path outside the install root.

---

## UNVERIFIED OBSERVATIONS (need additional files)

1. **Update feed signature verification** — Threat model item (a). No updater code supplied. Need: `src/SCSKiller.Core/Update/Updater.cs` (or equivalent) and whatever verifies the downloaded package before `Busy.Applying` is set. Check: Authenticode + pinned certificate + hash of payload verified *before* any file move; rollback protection (version floor).

2. **Shader container / cache parsing (CUE4Parse, `Rehydrate`, `PsoDb`, `ShaderIndex`)** — Threat model item (b). `Program.cs` references `CUE4Parse.Compression`, `Rehydrate.Run`, `PsoDb.Read`, `Middleware.Blobs` — all parse game-supplied bytes. Need: `src/SCSKiller.Core/Unreal/*`, `src/SCSKiller.Core/Planning/PsoDb.cs`, `Rehydrate.cs`, and any native parser in the C++ component. Check: length-prefixed reads, integer overflow in count fields, Oodle/zlib decompression bombs (size caps), and whether decompressed size is bounded before allocation.

3. **Proxy DLL (`d3d12.dll`) memory safety** — Threat model: loaded into the game process. Not supplied. Need: the C++ proxy source (device/PSO creation hooks, `scskiller.ini` parser, `scskiller.db` writer, attestation reader). Check: every length read from game-supplied shader blobs, the ini parser, and the attestation file format (`WriteAttestation`/`ArmedFile` — the managed side writes `pid=`/`pid_time=`; verify the native side bounds-checks).

4. **`Recordings.Merge` parser robustness** (feeds S5). Need: `src/SCSKiller.Core/Warming/Recordings.cs`.

5. **Vendor service `api.scskiller.com` client** — Threat model item (d). `RouteFailover.Product` is set but no HTTP code supplied. Need: `src/SCSKiller.Core/Vendors/*` and any `HttpClient` setup. Check: TLS validation not disabled (`ServerCertificateCustomValidationCallback`), certificate pinning, and whether responses (e.g., `GameVerdicts`, reference imports) are authenticated and schema-validated before influencing `Refusal()` logic or compile plans.

6. **`Elevated.WriteResult` / `Elevated.ReadAnswer` / `Elevated.Run`** (feeds S7). Need: `src/SCSKiller.Core/App/Elevated.cs`. Check: link-following on the result file, ACLs, and whether the elevated command line is fully app-controlled.

7. **`Codecs.DownloadOodle` / `ZlibHelper.DownloadDll`** (feeds S6). Need: `src/SCSKiller.Core/Codecs.cs` or equivalent. Confirm the pinned hash/signature check exists and is fail-closed.

8. **`ProcessTree.Snapshot()` / `OthersRun`** — `OthersRun` treats "can't enumerate" as "a process runs" (fail-safe, good), but `ExeNamesIn` matching by bare filename (`Path.GetFileNameWithoutExtension`) means any process named like the game's exe anywhere on the system blocks cleanup (DoS only). Low risk; confirm no security decision other than cleanup timing depends on it.

9. **`WriteAttestation` / armed-file format** — `StartAttested` arms the recorder for pid+creation-time. If the attestation file (`ArmedFile`) in the game folder is writable by the game process, the game could re-arm the proxy for a *different* pid, defeating the offline-session isolation. Need: the attestation write/read code and its ACLs.

---

## SUMMARY (by severity)

| ID | Severity | Title |
|----|----------|-------|
| S6 | Critical (conditional) | Codec DLL download verification not visible |
| S1 | High | Command-line injection via `OfflineArguments` into `CreateProcessW` |
| S5 | High | Untrusted `scskiller.db` merged into trusted recording store |
| S4 | Medium | Prefix-based ownership test in offline cleanup |
| S7 | Medium | Elevated `--result` file write to unvalidated path |
| S2 | Medium→Low | PID/creation-time TOCTOU residuals (largely mitigated) |
| S3 | Low | Mutex/RunOnce name collision via unsanitized `gameId` |
| S8 | Low | Piped-stdin consent bypass |
| S9 | Low | `fetch-codecs` exempt from update-exclusion gate |

The supplied code shows genuinely good hygiene in places (hash-gated cleanup deletion, creation-time-pinned PID checks, journaled file placement, suspended-start attestation). The most consequential confirmed issues are **S1** (unsafe command-line construction at a trust boundary) and **S5** (unauthenticated ingestion of game-process-controlled data into the trusted store). **S6** is potentially Critical but its mitigation likely lives in a file not supplied — it should be verified first.

## CHUNK 3

I'll perform a focused security audit of the supplied files. Let me analyze each component carefully.

## Analysis

**warm.cpp** - The warm host executable:
- Parses command-line args, stages files, launches child process
- Uses `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32` for AGS (good)
- `--stage-path` validation checks for `..`, `.`, invalid chars (good)
- `quoted()` function for command-line escaping - need to verify correctness
- Creates child via `CreateProcessW` with `cmd.data()` - mutable string required, OK
- The `parse()` function: `wcstol`/`_wcstoui64` with `end` pointer validation - checks `if (end && (*end || v.empty())) return false;` — but note `end` is only set for numeric options; for string options like `--stop-event`, `end` stays `nullptr` from initialization... wait, `end` is declared at loop top `wchar_t* end = nullptr;` and only numeric parsers set it. For `--stop-event` etc., `end` remains null, so the check `if (end && ...)` is skipped. OK.
- `--skip-keys` parsing: `nib(v[c])` — for hex chars, `iswxdigit` validates first. `nib` for 'A'-'F': `(x | 0x20) - L'a' + 10` works. OK.
- `parse()` loop: `for (; i + 1 < argc; i += 2)` — requires pairs. Returns `i == argc`. OK.
- Staging: `CreateDirectoryW` for `stage-<pid>-<n>` — attacker with write access to workdir could pre-create these? The workdir is chosen by the caller. If workdir is world-writable, a local attacker could pre-create `stage-<pid>-1` etc. But `CreateDirectoryW` failing with `ERROR_ALREADY_EXISTS` just tries next n. Then files are copied into a directory the attacker owns → the staged exe/dll could be replaced. But who controls workdir? The parent app (SCSKiller Core, not supplied). This is a TOCTOU/privilege concern but depends on workdir ACLs — unverified.
- `put()` uses `CopyFileW(..., TRUE)` — fail if exists. Good, prevents overwrite of pre-planted files. But wait — if attacker pre-created the staging dir and planted `d3d12.dll`, `CopyFileW` with TRUE fails → `fail()`. So pre-planting fails closed. Good.
- However: `CreateHardLinkW` for `scskiller_gen.db` — hard link to `work + L"scskiller_gen.db"`. If workdir file is attacker-controlled and later modified, the proxy reads it. But that's the threat model (game-supplied db). The proxy parses it — proxy.cpp not supplied, so db parsing bugs unverifiable.
- `--d3d12` staging: loads `D3D12Core.dll` with `DONT_RESOLVE_DLL_REFERENCES` to read `D3D12SDKVersion` export. `GetProcAddress` on a DLL loaded with DONT_RESOLVE_DLL_REFERENCES — reading exported data is generally safe (no DllMain runs). OK.
- Size check: `a.nFileSizeHigh || a.nFileSizeLow > 64u << 20` — skips files > 64MB. Comment says 5MB but check is 64MB. Minor.
- The child: `LoadLibraryW((dir + L"d3d12.dll").c_str())` — loads the staged proxy from its own dir. OK since staged.
- `quoted()` — let me verify: standard CommandLineToArgvW escaping. For each char: count backslashes; at end, append 2n backslashes + quote. For a quote char: 2n+1 backslashes then the quote... wait: `q.append(a[i] == L'"' ? 2 * n + 1 : n, L'\\') += a[i];` — for `"`, appends 2n+1 backslashes then `"`. Correct per MS rules (backslashes before a quote are doubled, quote itself escaped). For normal chars, n backslashes (literal). Correct.
- Command line built as `L"\"" + stage + exe + L"\" " + args` — stage path quoted, args individually quoted via `quoted()`. OK.
- `--package` path: uses IDesktopAppXActivator with args string. Same quoting.
- Environment: strips `RESHADE_*` vars. Good defensive measure.
- Named pipes `SCSKiller.Warm.<pid>.<fd>` — created with default security (NULL DACL → default). Local attacker could connect to the pipe first? `CreateNamedPipeW` with max instances 1. The child connects with `CreateFileW`. A local attacker in the same session could create a pipe with that name first (if they know the PID) — but the parent creates it before launching child. Attacker could connect to parent's pipe and write fake output that gets relayed to stdout — output spoofing, low severity. Or attacker creates pipe `SCSKiller.Warm.<pid>.1` before parent? Parent's CreateNamedPipeW with nMaxInstances=1 — if attacker created it first, parent's call fails → fail closed. Child connecting: attacker could race to connect to the pipe — ConnectNamedPipe accepts first connection; attacker writes garbage → relayed to stdout as if from child. JSON protocol spoofing. Medium-low. Also child side: `CreateFileW(pipe_name...)` — if attacker creates a pipe server with that name before parent... parent fails. OK.
- Heartbeat file mapping `Local\SCSKiller.Beat.<pid>` — created with NULL security attributes → default DACL. Another process in the same session (Local namespace) could open it and manipulate the beat counter → cause PAUSE/RUN confusion. `OpenFileMappingW` in child with FILE_MAP_READ. Attacker could create the mapping first with same name? Parent creates before child launch; attacker would need to pre-create before parent runs and guess PID. DoS-ish, low.
- `OpenProcess(SYNCHRONIZE, FALSE, parent_pid)` in child — parent PID from argv. Fine.
- Events: `SCSKiller.Final.<pid>`, `SCSKiller.Started.<pid>` — Local namespace, default security. Attacker in session could set them → premature exit code acceptance (`last_line` check uses final_event). If attacker sets Final event, then kills child with exit code 3... the parent checks `code != 3 || !last_line` — if attacker sets final event and the child dies with code 3 (e.g., abort()), parent treats it as retry → returns 3 → caller retries. Minor logic influence; attacker would need session access. Low.
- `TerminateProcess(pi.hProcess, 3)` etc. fine.
- Env vars `SCSKILLER_WARM_EXIT_S` read via GetEnvironmentVariableW with 16-char buffer; `_wtoi` — fine.
- The `--layer` staging: copies `.dll`, `.ini`, `.addon*` files from a folder into stage. These DLLs get loaded by the game/proxy in the child (ReShade layer). The layer folder path comes from CLI args — ultimately from the app. If a game ships a malicious "layer", it runs in the child. But that's the documented purpose (running game's layer). Threat model says game process is adversarial — the layer runs with user's privileges. This is by design but worth noting: the ini check for AddonPath/BasePath uses `GetPrivateProfileStringW` with 8-char buffer — checks if value is non-empty. Wait: `if (!_wcsicmp(x.c_str(), L".ini") && GetPrivateProfileStringW(sec, key, L"", v, 8, (stage + n).c_str()))` — returns number of chars copied; non-zero if key exists and non-empty → fail. Good.
- `_wcsnicmp(x.c_str(), L".addon", 6)` — extension check: `.addon` prefix match allows `.addonfoo`. Minor.
- Note: directory_iterator follows symlinks? `e.is_regular_file(ec)` — a symlink to a file is... directory_iterator with default options follows directory symlinks; `is_regular_file` on a symlink entry returns status of the link itself (not followed) — actually `is_regular_file()` uses `symlink_status`, so a symlink to a regular file returns false → skipped. OK.
- `unput`/`Unstage` cleanup: deletes staged files. `MoveFileExW` without MOVEFILE_REPLACE_EXISTING — if attacker pre-planted `scskiller.log` in flat... flat was freshly created by this process (CreateDirectoryW succeeded → didn't exist). But if workdir is attacker-writable, attacker can't preempt flat since it's new. OK.
- `stage_path` handling: builds subdirs under flat. Validation rejects `..`, `.`, empty, invalid chars, control chars. Also requires last component == exe. Looks solid. `GetFullPathNameW` length check.
- Wait — one issue in `parse()`: `--sdk` uses `wcstoul` — fine. But `--threads` etc. don't validate `end` before use... they do at bottom: `if (end && (*end || v.empty())) return false;`. But `end` is shared across the `if/else` chain — for `--skip`/`--isolate`, `end` is set by inner loop and then `end = nullptr;` reset at the end of that branch. For `--skip-keys`, `end` remains nullptr → check skipped. OK.
- `--skip` parsing: `_wcstoui64(c, &end, 10)` — if `end == c` (no digits) return false. Checks `*end && *end != L','` → false. OK.
- Integer overflow: `--memory-mb` `wcstoul` cast to uint32_t — fine.
- `--threads` negative? `(int)wcstol` — negative threads passed to proxy. Proxy not supplied. Unverified.
- `child()`: reads `scskiller_pass.bin` — size check `< (1ll << 31)`, resize, ReadFile. Compares `pass_of.size() != p[1]` (total items). OK.
- `emit` uses vprintf with fmt from code only. OK.
- `json()` escapes quotes, backslashes, control chars. OK.
- `crashes(&crashed, &isolate)` returns "JSON array bodies" from the proxy — inserted raw into JSON output (`\"crashed\":[%s]`). If proxy returns malicious strings... but proxy is ours. However the content derives from db keys (SHA1 hex of items) — presumably hex digits. Proxy.cpp not supplied; if it emits raw db content, JSON injection into the protocol → the caller (Core app) parses it. Unverified observation.

**warm11.cpp** - D3D11 shader replay, parses DXBC bytecode from game-supplied db:
- This parses untrusted DXBC shader containers (threat model b). Memory safety critical.
- `u32()`: bounds-checked read (`o + 4 <= s.size()`). OK.
- `chunk()`: checks `c.size() < 32`, reads count at offset 28, iterates `i < n && i < 64`. `size_t o = u32(c, 32 + 4 * i)` — offset table read: `32 + 4*i` max = 32+4*63 = 284; u32 checks `o+4 <= size` returns 0 if OOB. Then `len = u32(c, o + 4)` — o from file; if o+4+4 > size, u32 returns 0 → len 0. Check `o + 8 + len <= c.size()` — o and len are uint32 from file; `o + 8 + len` is size_t arithmetic (o is size_t, len uint32_t promoted) — no 32-bit overflow since size_t is 64-bit. But wait: `size_t o = u32(...)` — max 0xFFFFFFFF; `o + 8 + len` max ~0x1FFFFFFFE — fits size_t. And memcmp at `c.data() + o` only if check passes. OK. Looks safe.
- `signature()`: `size_t b = u32(d, 4) + e * size + lead` — u32(d,4) is element offset; e*size max 127*32; b could overflow? u32 max 4G + 4064 + 4 → ~4G, fits size_t. Check `b + size - lead > d.size()` → break. `name = u32(d, b)` — b bounds-checked? `u32(d, b)` checks `b+4 <= d.size()` internally, returns 0 if OOB. But then `name >= d.size()` check. `strnlen(d.data() + name, d.size() - name)` — bounded. OK.
  - Wait: `b = u32(d, 4) + e * size + lead` — the check is `if (b + size - lead > d.size() || name >= d.size()) break;` — but `name = u32(d, b)` is computed BEFORE the check in the same declaration statement: `size_t b = ..., name = u32(d, b);` — u32 is internally bounds-checked, returns 0 if OOB. So no OOB read. OK.
  - `d[b + 20]` — b+20 < b+size-lead ≤ d.size() since size-lead ≥ 20 (24-0=24, 28-4=24, 32-4=28). OK.
- `parse()` (SHEX token stream): 
  - `t = (const uint32_t*)shex.data(); nt = shex.size()/4;` — if shex.size() < 8, `nt < 2` → false. OK.
  - Loop: `op = t[p] & 0x7FF; n = op == OP_CUSTOMDATA ? (p+1 < nt ? t[p+1] : 0) : (t[p] >> 24) & 0x7F;` — for CUSTOMDATA, n = t[p+1] — full 32-bit dword count. Check `if (!n || p + n > nt) break;` — p+n: size_t, no overflow. OK.
  - Extended token skipping: `if (t[p] >> 31) while (q < end && t[q++] >> 31) {}` — bounded by end. Then `if (q < end && t[q++] >> 31) while (q < end && t[q++] >> 31) {}` — operand token + its extended tokens. `reg = q < end ? t[q] : ~0u`. OK, bounded.
  - `s.type = t[0] >> 16` — version token; type is bits 16-31? Actually D3D10_SB version token: bits 0-3 minor, 4-11 major, 16-31 program type... wait program type is bits 16-23? Version token: [31:16] = shader type? Actually D3D10_SB: bits 16-23 program type, 24-31? Hmm, `t[0] >> 16` gives up to 16 bits; compared against 0-5 later in warm11_item (`s.type != program_type[stage]`). OK, validated.
  - `s.interp[reg]` guarded `reg < 32`. `cmp_samplers` guarded `reg < 16`. OK.
  - OP_DCL_RESOURCE: `ctl = t[p] >> 11` — wait, `ctl` is `t[p] >> 11` — but for opcode token, bits 11-30 hold opcode-specific controls. `ctl & 0x1F` = resource dimension (bits 11-15). OK.
  - `s.srv.push_back` — unbounded number of declarations? Loop bounded by nt tokens; each iteration pushes at most one. Memory bounded by input size. OK.
- `partner_vs()`: builds HLSL from signature names — `e.name` comes from untrusted shader bytecode! `f += ... + e.name + std::to_string(e->index) + ";"` — e.name is arbitrary string from ISGN chunk (strnlen-bounded but content unrestricted). This is compiled with D3DCompile. HLSL injection: a crafted semantic name like `x;void evil(){...}` could inject HLSL code. But the compile is local, no privilege escalation — the compiled VS runs in the warm process. Impact: attacker-controlled HLSL compiled and run as a VS in the child process — but the child already runs attacker-influenced shader bytecode (the game's shaders) via draws... wait, no: the draws are indirect with zero counts — "no game shader code ever runs" deliberately. But HLSL injection via semantic name → compiled → used as partner VS → drawn with zero counts → doesn't execute either. Still, D3DCompile parsing malicious HLSL — compiler bugs? Also `iequal(e.name, "SV_Target")` etc. The semantic name with weird chars could break compilation → just fails. Severity: low-medium. But also `e.name` used in `D3D11_INPUT_ELEMENT_DESC` — `.SemanticName = e.name.c_str()` — pointer into `s.in` vector element's std::string — lifetime OK (s outlives call). CreateInputLayout validates semantics. OK.
  - Actually more interesting: semantic names with embedded NUL? strnlen stops at NUL; std::string constructed up to NUL. OK.
- `srv()`/`uav()`: `s.extra > 2048` check for structured stride. `samples = clamp(s.extra, 1, 32)` — but CreateTexture2D with sample count 32 might fail → returns null → error path. OK.
  - `key` for views cache: `(uint64_t)s.op << 56 | s.dim << 48 | s.ret << 40 | ...` — collisions possible (op is up to 0xA2 — 8 bits OK; dim 5 bits, ret 4 bits). Collision → wrong view reused → wrong binding, not memory unsafe. Low.
  - `vd.Texture2DArray = {0,1,0,1}` set for all texture dims — union member; for non-array dims the runtime reads relevant member. Setting wrong union member is harmless since only the dimension-appropriate member is read. OK.
- `warm11_item()`: stage index: `if (stage > 6 || s.type != program_type[stage])` — `program_type[stage]` with stage ≤ 6 — array has 7 entries. But stage could be 0? `program_type[0] = ~0u` — s.type can't equal ~0u? `s.type = t[0] >> 16` — could be 0xFFFF! If crafted shader has type bits = 0xFFFF and stage == 0... `stage > 6` check: stage comes from the db item (proxy.cpp, not supplied). If stage==0 passed and s.type==0xFFFF → passes check! Then `switch (stage)` — no case 0 → `sh` stays null, hr = E_FAIL → `if (FAILED(hr)) return ...`. OK, fails safe. But wait — `program_type[] = {~0u, 1, 0, 4, 3, 2, 5}` — index 0 → ~0u. s.type = t[0]>>16 — for a real DXBC, type is 0-5. Crafted could be 0xFFFF. Then check passes for stage 0, switch has no case → hr=E_FAIL → return false. Safe.
  - `ie.size() > 32` check for input layout. `stride = ie.size() * 16` — vb is 32*16*3 = 1536 bytes; stride max 512, 3 vertices → 1536. OK. But DrawInstancedIndirect with zero counts — no draw. OK.
  - `uavs + uav_from` — uav_from = nrt ≤ 8; uavs array is D3D11_1_UAV_SLOT_COUNT (64). nuav ≤ uav_slots ≤ 64. `nuav - uav_from` could exceed... nuav ≤ 64, uav_from ≤ 8 → count ≤ 64, pointer uavs+8, count up to 64 → reads up to uavs[71]?? Wait: `OMSetRenderTargetsAndUnorderedAccessViews(nrt, rtvs, ..., uav_from, nuav > uav_from ? nuav - uav_from : 0, uavs + uav_from, counts)` — UAVCount = nuav - uav_from, array starts at uavs + uav_from, so highest index accessed = uav_from + (nuav - uav_from) - 1 = nuav - 1 ≤ 63. OK. But `counts` array is `UINT counts[D3D11_1_UAV_SLOT_COUNT]` = 64 — OK. But hold on: u.reg < v->uav_slots (8 or 64 depending on FL). nuav = max(u.reg+1) ≤ uav_slots ≤ 64. OK.
  - `rtvs[e.index]` guarded `e.index < std::size(rtvs)`. OK.
  - `topos[s.gs_prim]` — guarded `s.gs_prim >= std::size(topos)`. gs_prim = ctl & 0x3F ≤ 63. OK.
  - `D3D11_PRIMITIVE_TOPOLOGY_1_CONTROL_POINT_PATCHLIST + hs.cp_in - 1` — cp_in validated 1..32. OK.
- `warm11_pair()`: cp checks OK.
- `warm11_flush()`: busy loop on GetData — if device removed, GetData returns error → exits. OK.
- `warm11_drain`: `strnlen(m->pDescription, m->DescriptionByteLength)` — bounded. OK.

Overall warm11.cpp parsing is remarkably defensive. The HLSL injection via semantic names is the notable one — but impact is limited (compiled partner VS drawn with zero-count indirect args; and even if it ran, it runs in the warm child which is already processing hostile shaders by design; no privilege boundary crossed — the child runs as the user). Actually wait — could injected HLSL cause the *compile* itself to do something? D3DCompile runs in-process; a compiler crash → DoS. HLSL injection could also produce a valid shader that... does nothing at draw with 0 instances. I'd rate Low.

Hmm, but also: `partner_vs` uses `e.name` — names with characters like `:` or `;` break compilation → logged, skipped. Not exploitable beyond DoS of that item.

**vtslots.cpp** — static_asserts only, not linked. No risk.

**vk_spirv.py** — build-time codegen. Runs glslang on generated sources. `subprocess.run([glslang, ...])` with list form — no shell injection. glslang path from argv. Build-time only. No runtime risk. Writes vk_spirv.h next to script. Fine.

**warm.manifest** — segment heap setting. No security issue.

**release-sign/Program.cs** — offline signing tool:
- `OutsideGit()`: runs `git -C <dir> rev-parse --show-toplevel` to ensure key file outside git. Fails closed if git errors unexpectedly. But: if `git` isn't on PATH, `Process.Start` throws Win32Exception → caught → error message, return 1. Fails closed. OK.
- However: `git rev-parse` exit code 0 check — a malicious repo could... this is about protecting the key from being committed. If dir is inside a repo but git is fooled (e.g., GIT_DIR env var? Process.Start inherits environment — `GIT_DIR`/`GIT_WORK_TREE` env vars could make rev-parse report not-in-repo or fail!). Attacker scenario: trick admin into running keygen with GIT_DIR set → key written inside repo → committed. Weak-ish; env manipulation on admin machine is out of typical scope. Also `git -C dir rev-parse` — if dir contains a malicious `.git` with hooks? rev-parse doesn't run hooks. Config could alias? rev-parse isn't aliasable... `git rev-parse` could be affected by `.git/config` `core.fsmonitor`? Not executed for rev-parse. Low.
- `Sign()`: reads seed, zeroes after. Writes `.sig` via `File.WriteAllText(feed + ".sig", ...)` — overwrites existing sig. Fine for a signing tool.
- `keygen`: `FileMode.CreateNew` — never overwrites. Good.
- `Verify()`: uses `FeedTrust` with a fresh temp dir as replay store — `Directory.CreateTempSubdirectory("release-sign-")`. FeedTrust.cs not supplied — the actual crypto (Ed25519 presumably: "32-byte Ed25519 seed") can't be verified. Unverified observation: FeedTrust.Accept implementation (signature verification, replay protection, channel binding) is in src/SCSKiller.Core/App/Updates.cs — not supplied. The threat model explicitly mentions update feed signature — the critical verification code is NOT in the supplied files. Must note this.
- `Known()`: validates option names are known and even count. `Opt()` — `Array.IndexOf(o, name)` then `o[i+1]` — if name is last element (odd position), Known ensures even length and names at even indices, so i+1 exists. OK.
- `ChannelOf`: regex `^releases\.([a-z]+)\.json$` on filename; validated against `UpdateChannels.All`. OK.
- Catch filter: catches specific exceptions. `FormatException` from `Convert.FromBase64String`. OK.
- One thing: `Sign` writes sig with `File.WriteAllText` — default UTF-8 no BOM. Fine.
- `Verify` with `--pub`: attacker-supplied pub key — it's a verify tool, admin chooses. Fine.

Now, the threat model items:
(a) update feed/signature — FeedTrust not supplied → UNVERIFIED, need Updates.cs.
(b) game-shipped files SCSKiller parses — scskiller.db / scskiller_gen.db parsing is in proxy.cpp (not supplied). warm11.cpp parses DXBC from the db — audited, looks solid. The db container parsing itself unverified.
(c) game process injected into — proxy.cpp not supplied (vtable patching, IPC).
(d) api.scskiller.com responses — not in supplied files (Core app). Unverified.

Concrete findings to report:

1. **Named pipe / event / shared-memory IPC spoofing (Local namespace, NULL DACL)** — warm.cpp: `CreateNamedPipeW`, `CreateEventW`, `CreateFileMappingW` all with `nullptr` security attributes → default DACL grants access to processes running as the same user in the same session. A local attacker (same user, e.g., the compromised game process — threat model c!) can:
   - Connect to `\\.\pipe\SCSKiller.Warm.<pid>.1` before the child does → inject arbitrary JSON lines into the parent's stdout relay → the Core app parses forged "done"/"retry" events → e.g., report success while warming failed, or forge "crashed" item lists influencing retry logic. Also can connect to pipe .2 (stderr).
   - Open the beat mapping with FILE_MAP_WRITE (child opens read; mapping created PAGE_READWRITE) → manipulate heartbeat → force PAUSE/RUN.
   - Set `SCSKiller.Final.<pid>` event → combined with killing child... attacker can't easily kill child (same user — actually yes they can, same user!). Hmm, same-user attacker can TerminateProcess the child anyway. So the event spoofing adds: exit code 3 + final event set → parent returns 3 (retry) instead of error. Or set Started event to defeat the stuck-layer timeout.
   Severity: the threat model includes "the game process SCSKiller injects into" as adversarial — that process runs as the same user, so it can do all this. Impact: protocol spoofing → the app misreports warm state; potentially tricks retry logic. Not memory corruption. Medium. But wait — pipes: child connects with CreateFileW; attacker could also create the pipe server first? Parent creates first (before child launch) with nMaxInstances=1. Attacker creating same name after → fails. Attacker connecting as client → wins race vs child. Child then fails to connect → `continue` → child's stdout stays inherited... wait, in package mode, child launched via activator with no inherited handles — if pipe connect fails, child output lost. Attacker wins race → relays attacker's data. Yes.
   Also `SCSKiller_Control` states via... control is via child's own call. OK.
   Fix: use security descriptors restricting to the process (e.g., DACL with only the user's SID + deny others, or better: use ACL with only SYSTEM/self; for pipes use PIPE_REJECT_REMOTE_CLIENTS? That's for remote. For same-session same-user, can't fully exclude same-user processes — but that's inherent: same-user attacker is already strong. Still, standard hardening: explicit DACL. Realistically, same-user game process can inject into child anyway (OpenProcess + CreateRemoteThread as same user!). So severity is bounded — the game process could just debug/inject the child directly. Given that, this is Low-Medium. I'll report as Medium with honest reasoning... Actually since a same-user process can already OpenProcess(PROCESS_ALL_ACCESS) the child and parent, the IPC spoofing adds nothing. Hmm — unless the child runs with package identity (--package): packaged processes have different capabilities; a same-user non-packaged process can still OpenProcess? Packaged app processes: same user can open them (no admin needed) generally yes. So the IPC hardening is defense-in-depth. I'll report as Low/Medium — let me settle: Medium for pipe output spoofing (direct protocol injection into the Core app's JSON parser — if that parser has bugs, it's an attack surface amplifier), noting same-user caveat.

2. **HLSL injection via untrusted semantic names** — warm11.cpp `partner_vs()`: semantic names from game-supplied DXBC are interpolated into HLSL source compiled by D3DCompile. Crafted name → arbitrary HLSL. Impact: code executes... at compile time nothing executes; the compiled shader is drawn with zero-count indirect args so no shader code runs. But: D3DCompile with injected source — attacker could make compile hang (DoS of warm) or exploit a compiler bug (fxc is not hardened against malicious source? it's a Microsoft component; bugs exist but speculative). Also injected HLSL could declare semantics that change `lines_up` outcome? lines_up compares consumer inputs vs compiled outputs — injected code could add outputs... The partner VS is used for PS/GS/HS warming. Even if attacker gets a malicious VS compiled and bound, draw is zero-count → no execution. So real impact: minimal. Severity Low. Confidence High that the injection exists; Low that it's exploitable beyond DoS. Report as Low.

3. **`--layer` DLL staging executes game-supplied code in the warm child** — by design ("a layer's code still runs"). The layer folder is copied wholesale (.dll/.ini/.addon). If the game (threat model b/c) ships a malicious ReShade layer, warming loads it into the child process → arbitrary code execution as the user in the warm child. But the child is spawned specifically to mimic the game; the game could just run its own code anyway (it's a game process — already executes as user). So no privilege gain: the game already has code execution as the user. Unless SCSKiller runs elevated? Not indicated. I'd call this by-design; note as observation, not a finding. Actually — the ini check prevents AddonPath redirection, showing they thought about confining the layer. The layer is a copy of the game's actual layer, which the game would load anyway. Not a vuln. Skip (mention in observations).

4. **Staging directory pre-creation / workdir trust** — if workdir is attacker-writable, attacker pre-creates `stage-<pid>-<n>` for n=1..99 → all CreateDirectoryW fail with ERROR_ALREADY_EXISTS → loop ends after 99 → fail. Just DoS. If attacker pre-creates only some, the tool uses a pre-existing attacker-owned dir? No — CreateDirectoryW succeeds only if it created the dir. If it already exists, ERROR_ALREADY_EXISTS → tries next. So it never uses a pre-existing dir. Good. But files copied INTO the fresh dir — attacker with write access to workdir can still modify files in the new subdir after creation (dir ACLs inherit workdir's). Race: replace staged d3d12.dll after CopyFileW before child launch → proxy DLL swapped → child loads attacker's DLL → code exec in child (same user). Again same-user attacker → already has code exec. But wait — threat model (b): "files a game ships that SCSKiller parses" — the workdir contains scskiller.db from the game. If the game's installer wrote the workdir with loose ACLs... The bigger issue: no integrity check on staged inputs — but they're the game's files by design. The proxy d3d12.dll comes from `bin` (install dir) — should be protected by installer ACLs. OK, observation only.

5. **`parse()` accepts `--sdk` from command line and child sets `D3D12SDKVersion` export before loading proxy** — fine.

6. **`--pass` file size vs db total mismatch check** — present. OK.

7. **`warm.cpp` child: `OpenFileMappingW(FILE_MAP_READ, ...)` then `MapViewOfFile(beat_map, FILE_MAP_READ, 0, 0, sizeof(LONG))`** — if attacker created the mapping smaller than sizeof(LONG)? Attacker would need to create it before parent — parent creates it before child launch; attacker pre-creating requires predicting PID and winning race before parent creates it. If mapping exists already, CreateFileMappingW returns existing object (with existing size!) — GetLastError ERROR_ALREADY_EXISTS not checked! If attacker (same session) pre-creates `Local\SCSKiller.Beat.<pid>` with size 0 or 1 byte before the parent creates it... but attacker needs to know the parent's PID before it starts — PIDs are guessable (brute force: create mappings for a range of PIDs!). Attacker could pre-create beat/final/started objects for many PIDs. Then parent's CreateFileMappingW opens the existing one (size too small) → MapViewOfFile of 4 bytes on a 1-byte mapping → the view... mapping smaller than requested → MapViewOfFile fails or returns view where accessing beyond size → AV. Actually MapViewOfFile with size 4 on a 1-byte section: succeeds? The view size can exceed section size? No — MapViewOfFile fails if the requested size exceeds the section size? Per docs: "If the section is smaller than the requested size, MapViewOfFile fails"? Actually MapViewOfFile: dwNumberOfBytesToMap — if it extends beyond the end of the section, the call fails? Let me recall: For file mappings, mapping beyond section size → error. Yes, MapViewOfFile fails with ERROR_INVALID_PARAMETER if size exceeds section. Then beat = null → `if (!beat) return fail(...)` — fails closed (DoS). Similarly CreateEventW for existing event returns existing handle — attacker pre-created events → attacker controls them (they're auto/manual reset as attacker chose; attacker can SetEvent at will). Parent doesn't check GetLastError() == ERROR_ALREADY_EXISTS for final_event/started either. Impact: attacker pre-seeds named objects for predicted PIDs → forces `last_line` true / started true → influences exit-code handling: child dying with code 3 without printing retry → treated as retry (return 3) → caller retries indefinitely? Or started event pre-set → disables the hang watchdog. Severity: Low-Medium (same-user attacker again; but pre-seeding PID-named objects is a classic squatting issue). Given same-user attacker already has strong powers, I'll fold this into the IPC finding as one finding covering all named-object squatting/spoofing, severity Medium, confidence High that the code lacks checks.

Actually let me reconsider severity calibration. The threat model says the game process is adversarial. The game runs as the same user. A same-user process can already: inject into warm child, replace files it can write, etc. So named-object spoofing gives no new capability EXCEPT in the --package case where the child runs with package identity — a packaged process is still same-user though. The genuinely distinct impact: forged JSON into the Core app's parser (the relay writes attacker bytes to parent's stdout → Core reads them). If Core's JSON parser trusts fields (e.g., paths in "stage" event?), could escalate. Core not supplied. Medium, honest.

8. **release-sign: `git` trust for OutsideGit** — environment-influenced (PATH hijack: a malicious `git.exe` earlier in PATH on the admin machine → ExitCode 0 always? No wait — exit 0 means "inside repo" → throws. A malicious git could exit nonzero with "not a git repository" → key allowed inside repo). PATH hijack on the signing machine is out of scope mostly, but a defense-in-depth note: resolve git path / don't rely on external tool. Low. Confidence Medium. Actually the failure mode: key file inside a git repo → risk of accidental commit of the private key. The check is a safety rail, not a security boundary. Low.

9. **`Verify()` replay store**: uses a fresh temp dir → "nothing seen yet" → replay protection bypassed in verify tool — but that's just the offline verifier; the client's store is in AppStore. Fine, by design for verify tool.

10. **`Sign()` — no confirmation that feed parses / channel matches content** — signing tool signs arbitrary bytes. Fine.

11. **warm11.cpp `chunk()` — `u32(c, o + 4)` where `o` itself from file**: o+4 could overflow uint32? o is size_t (from uint32 value), o+4 ≤ 0x100000003, fits size_t; u32 checks `o+4 <= s.size()`. Safe.

12. **`signature()` — `std::string(d.data() + name, strnlen(...))`** — name < d.size() checked. Safe.

13. **`parse()` SHEX: `shex.data()` when chunk returns empty → nt<2 → false. Safe. But note: `chunk` returns first matching fourcc; duplicate chunks not handled — fine.

14. **`partner()` cache key**: `s.in_raw + interp bytes + type` — in_raw includes fourcc + raw chunk; collisions unlikely; not security.

15. **`warm11_item` — `ie.push_back` with `e.name.c_str()`** — D3D11_INPUT_ELEMENT_DESC stores pointer; `s.in` alive during CreateInputLayout. OK. But `ie` may contain semantic names with embedded special chars — CreateInputLayout validates. OK.

16. **Missing check: `stage` lower bound in warm11_item** — `stage > 6` checked, but stage is uint32 from item; stage 0 handled (fails safe as shown). OK.

17. **`uav()` key: `s.extra << 8`** — extra up to 2048 (checked) — wait, check happens after key computation? `uint64_t key = ... | s.extra << 8 | s.reg << 1 | cs;` computed BEFORE `if (!s.extra || s.extra > 2048) return nullptr;`. For OP_DCL_UAV_STRUCTURED with huge extra: key uses extra<<8 — extra is uint32; `s.extra << 8` — uint32 shift → could overflow into dim/ret bits? s.extra << 8 as uint32_t: extra up to 0xFFFFFFFF → <<8 overflows (UB? no — unsigned shift is defined, wraps). Collision in cache key → wrong cached view returned for a different declaration → wrong resource bound → driver compile mismatch, not memory unsafe (views are valid objects). Then the extra>2048 check returns nullptr → error. Wait order: key computed, `auto& view = v.views[key]; if (view) return ...` — cache lookup BEFORE validation! If a previous valid structured UAV with extra=0x100 (256) created key K, and now a malicious shader declares extra=0x100000100?? extra is uint32_t, max 0xFFFFFFFF. extra<<8 wraps: 0xFFFFFF00 << 8 = 0xFFFF00... let me compute: (0xFFFFFF00u << 8) = 0xFFFF0000 (32-bit wrap). Could collide with another (op,dim,ret,extra,reg,cs) tuple? The key packs op(8)|dim(8)|ret(8)|extra<<8 — extra<<8 overlaps ret bits! key = 1<<63 | op<<48 | dim<<40 | ret<<32 | extra<<8 | reg<<1 | cs. extra<<8 can be up to 0xFFFFFFFF00 (wrapped) — bits above bit 32 overlap ret<<32 and dim<<40 fields! E.g., extra=0x1000000 → extra<<8 = 0x00000000_1000000... wait 0x1000000 << 8 = 0x100000000 — in 64-bit context? `s.extra << 8` — s.extra is uint32_t → shift done in 32-bit (int promotion: uint32 stays uint32) → 0x1000000 << 8 wraps to 0x00000000. So extra=0x1000000 gives same key contribution as extra=0! Then `| s.extra << 8` = 0. Collision with a raw UAV (extra=0)? op differs (0x9E vs 0x9D) → op<<48 differs. Collision between structured UAV extra=0x1000000 and structured extra=0x00?? extra=0 → returns nullptr (check !s.extra). Hmm: extra=0x1000000 (16M) → key same as extra=0... but then check `s.extra > 2048` → return nullptr. But the cache lookup happened first: `auto& view = v.views[key]; if (view) return cached`. If key collides with an existing valid entry → returns the WRONG cached view, bypassing the stride validation! Construct: first declare structured UAV stride 0x100 at u5 (valid, cached with key ...|0x100<<8|5<<1). Then declare structured UAV stride 0x1000100 at u5: extra<<8 = 0x100<<8 (wrap drops 0x1000000<<8's high bits? 0x1000100 << 8 = 0x00010000... let me compute: 0x01000100 << 8 = 0x00010000 (mod 2^32)? 0x01000100 * 256 = 0x100010000 → mod 2^32 = 0x00010000. And 0x100 << 8 = 0x10000. Yes! Collision. So second declaration hits cache → returns view created for stride 0x100 → the stride>2048 check is bypassed via cache hit. Consequence: a UAV view with mismatched stride bound to the shader's slot → D3D11 runtime validates binding against shader declaration at draw → debug layer error, draw fails or runtime handles it. Memory unsafe? The view is a valid object; binding a mismatched view is a runtime validation error, not memory corruption. So impact: negligible (item fails to warm). Not a real vuln — cache key collision causing wrong-but-safe behavior. Skip or Low. I'll skip — no security impact.

18. **`srv()` key**: `samples` or extra packed in low 32 bits: `(s.op == OP_DCL_RESOURCE_STRUCTURED ? s.extra : samples)` — extra up to 2048 checked... again check after cache lookup: `if (!s.extra || s.extra > 2048) return nullptr;` is AFTER `if (view) return cached`. Same wrap issue: key = op<<56|dim<<48|ret<<40|extra (no shift) — extra in low 32 bits, no overlap. Collision requires same op/dim/ret/extra — then it IS the same declaration. Safe. For UAV the <<8 overlap exists but impact nil as analyzed.

19. **release-sign `Known()`** — `o.Where((_, i) => i % 2 == 0).All(names.Contains)` — OK.

20. **`Opt()`** — returns o[i+1]; if name appears at odd index (as a value), IndexOf finds first occurrence — could find a value position! E.g., `sign feed --key --kid x` → o = ["--key","--kid","x"]? Known() requires even length and even positions in names. o.Length=3 odd → usage. OK. But `verify feed --pub --kid` → o=["--pub","--kid"], Known passes (both known names, even length). Opt(o,"--pub") → index 0 → returns "--kid" as the pub value! Then Convert.FromBase64String("--kid")... in Verify: keys = {[kid]="--kid"} — wait kid = Opt(o,"--kid") → index 1 → o[2] out of range! `Array.IndexOf(o, "--kid")` = 1, `o[i+1]` = o[2] → IndexOutOfRangeException — not caught by the catch filter (only ArgumentException, IOException, etc.) → crash with unhandled exception. DoS of a CLI tool — trivial. Also `--kid` value used in dictionary key. Not security. Skip (or trivial note). Actually unhandled exception in a release-signing tool — availability only, local admin tool. Skip per "do not pad".

21. **warm.cpp `emit("...%s...", crashed, isolate)`** — `crashed`/`isolate` strings from proxy (our DLL) — but content derives from db keys. If proxy emits unescaped db-derived content, JSON injection toward Core parser. proxy.cpp not supplied → UNVERIFIED observation.

22. **`child()` — `LoadLibraryW((dir + L"d3d12.dll").c_str())`** — dir is the staged dir; proxy staged by parent. If attacker replaced it (workdir writable race) → code exec. Same-user caveat. Observation.

23. **`ags_device` — `LoadLibraryExW(o.ags..., LOAD_LIBRARY_SEARCH_SYSTEM32)`** — loads game-supplied AGS DLL → code exec in child by design (it's the game's DLL; comment says so). AGS DLL is game-supplied → arbitrary code in child. Same-user, by design. Observation. Note: LOAD_LIBRARY_SEARCH_SYSTEM32 only affects search for imports — good practice, they did it.

24. **`--d3d12` staging loads game-supplied D3D12Core.dll** — by design (game's runtime). DONT_RESOLVE_DLL_REFERENCES for version read — safe; child loads it for real → game code in child, by design. Observation.

25. **Missing authenticode check on staged/loaded DLLs** — the app "must validate code signatures/hashes on anything it downloads and executes" — nothing downloaded here; all local. The update path is in Core (not supplied). Observation.

26. **`wcstoul(argv[2])` for parent PID** — child opens process with that PID; if bogus → OpenProcess fails → parent handle null → `WaitForSingleObject(parent, 0)` with NULL handle → returns WAIT_FAILED (not WAIT_TIMEOUT) → `stopping = true` immediately! Wait: `stopping = stopping || ... || WaitForSingleObject(parent, 0) != WAIT_TIMEOUT;` — if OpenProcess failed, parent=NULL → WaitForSingleObject(NULL,0) = WAIT_FAILED → stopping=true → child stops immediately. Fails safe-ish (child won't warm). Only reachable via direct CLI invocation with bad args. Not a vuln.

27. **Heartbeat DoS via `SCSKiller.Beat` read** — covered in IPC finding.

28. **`parse()` `--skip-keys` — `nib` for '0'-'9': `x <= L'9' ? x - L'0'`** — iswxdigit ensures 0-9a-fA-F. OK.

29. **JSON `emit` for retry: `\"failedItem\":%lld` with r[4]==~0 → -1** — fine.

30. **`warm11_open` debug flag** — enables D3D11 debug layer; fine.

31. **`warm11_flush` infinite loop if GetData keeps returning S_FALSE without device removal** — GPU hang → infinite Sleep(1) loop → the parent's watchdog (start_turns/final_turns) terminates child. OK.

32. **release-sign: `File.ReadAllText(OutsideGit(keyFile))`** — key file read; fine. Seed zeroed in finally. Good.

33. **`Directory.CreateTempSubdirectory("release-sign-")`** — creates in %TMP% with random name; deleted in finally. If process killed, leftover — no sensitive data (replay store). Fine.

Now the biggest gaps per threat model: FeedTrust (Updates.cs), proxy.cpp (db parsing, injection, vtable hooks, IPC with Core), Core update download (api.scskiller.com TLS, signature verification before execute). All NOT supplied → must list as unverified observations with needed files.

Let me also double-check `quoted()` once more with a tricky input: `a = L"a\"b"`. i=0: n=0 (a[0]!='\\'), append 0 backslashes + 'a'. i=1: a[1]='\\' → n=1, i=2: a[2]='"' stop counting. append(2*1+1=3 backslashes) + '"' → `\\\"` correct (backslash before quote doubled, quote escaped). i=3: 'b'. End: append 0 + '"'. Result: `"a\\\"b"` — CommandLineToArgvW reads: a, then \\\" → literal backslash + quote... `\\` → `\`, `\"` → `"`. Yes correct.

`parse()` — one more: options with empty value `--stop-event ""` → v empty; end==nullptr (string branch) → no empty check → stop_event empty → treated as none. OK.

`--threads` with `v.empty()` — wcstol("") → end==c_str, *end==0... check `if (end && (*end || v.empty())) return false;` → v.empty() → false. Good.

Negative `--start`? `_wcstoui64` on "-1" → huge value. start offset into items — proxy handles? Unverified but benign likely.

`--memory-mb` huge → uint32 wrap. Proxy-side. Unverified.

One more in warm.cpp: `for (int n = 1; n < 100 ...)` staging dir name includes PID — predictable; covered.

`Unstage` destructor: `MoveFileExW(stage+n, flat+n, 0)` — no REPLACE_EXISTING; flat freshly created so no pre-existing files — unless attacker planted them in flat between creation and move (workdir-writable attacker). Then move fails silently → outputs stay in stage dir which then... dirs removed only if empty (`RemoveDirectoryW` only if empty) → tree remains. Minor.

Also: `MoveFileExW` of `scskiller_failed.keys` etc. — fine.

**Privilege**: does warm.cpp run elevated? No indication. The manifest has no requestedExecutionLevel → runs as invoker. OK.

Let me also check `child()` pipe connect: `CreateFileW(pipe_name, GENERIC_WRITE, 0, ...)` — no SECURITY_IDENTIFICATION flags; server can't impersonate (child is client; parent only reads). Parent's relay: ReadFile then WriteFile to stdout — no impersonation (PIPE_ACCESS_INBOUND, client can't impersonate inbound-only? Impersonation requires PIPE_ACCESS_DUPLEX? Actually client needs SECURITY_IMPERSONATION in CreateFile; child passes 0 → anonymous → no impersonation). OK.

Relay thread: `CancelSynchronousIo` after 1s if child never connects — OK.

Now finalize findings list. Being rigorous:

**S1 (Medium)**: Named IPC objects (pipes/events/shared memory) created with NULL DACL and no existence check → same-session attacker (e.g., the hostile game process) can spoof/forge the JSON control channel and heartbeat, and pre-squat PID-predictable names. warm.cpp child()/wmain. Confidence High (code clearly lacks SDs and ERROR_ALREADY_EXISTS checks). Impact bounded by same-user equivalence; main value is forged protocol lines to the Core app and watchdog defeat.

**S2 (Low)**: HLSL injection via untrusted DXBC semantic names into partner_vs() source compiled by D3DCompile. warm11.cpp. Confidence High (injection exists), impact low (zero-count draws; compile-time only; potential fxc crash DoS).

**S3 (Low)**: release-sign OutsideGit() relies on `git` from PATH and inherited env → safety rail can be defeated (GIT_DIR/PATH), risking accidental commit of the release private key. Confidence Medium.

Anything else concrete? Let me reconsider `signature()`: `v.push_back({std::string(...), ...})` — fine.

`parse()`: `uint32_t reg = q < end ? t[q] : ~0u, next = q + 1 < end ? t[q + 1] : 0` — OK.

`OP_DCL_SAMPLER`: `reg < 16` guard. OK.

`warm11_item` stage==1: `ie.size() > 32` — but check happens after push loop; fine. `CreateInputLayout(ie.data(), ...)` with ie empty → skipped via `!ie.empty()`. OK.

`partner()` — `static std::atomic<int> logged` inside else-if — fine.

`buffer()`: `stride ? stride*16 : kBuf` — stride ≤ 2048 checked at call sites (srv/uav) → max 32KB. OK.

`texture()` samples clamped 1..32 — CreateTexture2D may fail for 32x → null → error. OK.

`view_format` — ret values other → R32_FLOAT. OK.

`warm11_pair` — `hs.cp_in > 32` check; `hs.cp_out != ds.cp_in` — cp_out from ctl&0x3F ≤ 63; ds.cp_in could be 0 → mismatch → reject. OK. Topology: 1_CONTROL_POINT_PATCHLIST + cp_in - 1, cp_in ≤ 32 → ≤ 32_CONTROL_POINT_PATCHLIST. OK.

vk_spirv.py — build-time; `subprocess.run([...])` no shell; writes header. The glslang binary path from argv — build machine concern. No finding.

manifest — no finding.

vtslots — no finding.

What about `warm.cpp` `put()` for `--layer`: `directory_iterator(o.layer)` — non-recursive. `.addon` prefix match `_wcsnicmp(x, L".addon", 6)` — extension like `.addonevil` passes; harmless (any dll already passes).

The ini check: only checks AddonPath/BasePath when the ini is staged — good. But `GetPrivateProfileStringW` with buffer 8: if value longer than 7 chars, returns 7 (truncated) → non-zero → fail. If value empty → 0 → pass. OK.

One subtle thing: `for (auto [sec, key] : {std::pair{...}, ...})` — fine.

`--stage-path` with package non-empty is ignored — documented. OK.

`child()` — `SetEnvironmentVariableW(L"SCSKILLER_MODE", L"warm")` — fine.

`D3D12SDKVersion = o.sdk` — exported variable written before LoadLibrary — fine.

Exit code handling: `if (code > 1 && (code != 3 || !last_line))` — code 2? Child returns... child returns 0/1/3/4. 4 handled. abort() → 3. OK.

Also `wmain` — `parse(argc, argv, 3, o)` — argv[1]=workdir argv[2]=exe. `exe.find_first_of(L"\\/")` rejected — exe must be bare filename. But exe could be `..`? `..` has no slash! `put(self, exe, false)` → CopyFileW(self, stage + L"..", TRUE) → fails (dest is a dir). Then fail. OK. exe = `d3d12.dll`? Then staged exe named d3d12.dll... `put(self, L"d3d12.dll")` copies the warm exe as d3d12.dll, then `put(proxy, L"d3d12.dll")` → CopyFileW fails (exists) → staging fails. Fail closed. OK. exe with trailing dot/space (Windows normalizes)? `stage + exe` — CreateProcessW with `game.` → normalizes to `game`? CopyFileW(self, "stage\game.") → creates file "game" (trailing dot stripped) → then CreateProcessW("...\game.") → runs "game" — consistent. OK.

`work` path: `work.back()` — if work empty string? argc≥3 ensures argv[1] exists but could be empty → `work.back()` on empty wstring → UB! `std::wstring work = argv[1]; if (work.back() != ...)` — empty string → back() undefined. Crash (reads before begin — likely returns garbage or asserts in debug). Invoking with empty workdir arg → crash. Local CLI misuse; the caller is the Core app. Low/trivial — not worth reporting? It's a robustness bug, attacker would need to control Core's invocation. Skip per no-padding... Actually a malformed argument from a compromised... the args come from Core (trusted local). Skip.

`--child` path: `wcstoul(argv[2])` no validation — covered above, fails safe.

OK also consider: `CreateNamedPipeW(..., 1, 0, 1 << 16, 0, nullptr)` — nMaxInstances=1, default SD. Covered in S1.

`CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(LONG), name)` — covered.

Now severity for S1: The game process (threat model c) is same-user. It can already inject into any same-user process. So S1 gives it nothing new EXCEPT when warm child runs under a package identity (--package) — packaged processes run with package capability but still same user SID; OpenProcess from same user works. Honestly S1 is defense-in-depth + protocol integrity. I'll say Medium-Low... The instructions want a single severity. Given forged "done" events could make the Core app believe warming succeeded, and potentially feed attacker-controlled strings into Core's JSON parser (a different, possibly more privileged component — Core might be a service? It's WPF desktop, same user). I'll assign Medium with clear caveats, confidence High on the code issue, and note impact limitation.

Hmm wait — one more important check: the pipe relay writes attacker bytes to the parent's stdout, which the Core app parses as JSON lines. If Core treats "event":"error" vs "done" etc. — pure spoofing. Also the attacker could emit HUGE data → memory exhaustion in Core? Relay copies 4KB chunks unbounded. Meh.

Also events: `started` event spoofed → disables stuck watchdog (TerminateProcess after start_turns). `final` event spoofed → exit code 3 accepted as retry without last line → infinite retry loop in caller? Caller goes by last line; if none... parent returns 3 with no retry JSON → Core might retry forever. DoS. Fold into S1 description.

Unverified observations to list:
1. FeedTrust.Accept / Sign / NewKey / ReleaseKeys implementation (Updates.cs) — the actual Ed25519 verification, canonicalization, replay store, channel binding, key pinning. Threat model (a). Need src/SCSKiller.Core/App/Updates.cs.
2. scskiller.db / scskiller_gen.db container parsing in proxy.cpp — untrusted game files parsed in-process (and in the injected proxy). Need proxy/proxy.cpp.
3. `SCSKiller_Crashes` returning JSON array bodies inserted raw into protocol — potential JSON injection if db-derived content isn't escaped. Need proxy.cpp.
4. Update download path: TLS validation, hash/signature check before executing installer, api.scskiller.com handling. Need Core update files.
5. Proxy vtable patching & injection mechanism into game process; IPC between proxy and Core; whether proxy validates the warm host (SCSKiller_WarmHost export check is trivially forgeable by any process exporting it — the comment says "the proxy warms only in a process exporting it" — any process can export it; is that a security boundary? Probably just an accidental-load guard).
6. Whether SCSKiller Core/warm runs elevated (installer/service) — would raise severity of staging/IPC issues.
7. `--threads`, `--start`, `--memory-mb` values passed to proxy without range validation — proxy-side handling unverified.
8. Workdir ACLs — staging inherits workdir permissions; if Core uses a world-writable temp dir, same-session file swap races (CopyFileW fail-if-exists mitigates pre-planting, but post-copy replacement of staged d3d12.dll before child load is possible by a same-user writer).

Also: `CreateHardLinkW` for scskiller_gen.db — hard link means the proxy reads the SAME file; if the game (or attacker) modifies work\scskiller_gen.db during the warm, the proxy sees changing content → parsing races. Proxy parsing unverified; note under db parsing observation. Also hard link creation requires the source not be... fine.

One more possible finding: **`Verify()` in release-sign uses a fresh temp replay store** — meaning the offline verify doesn't check replay — but that's intentional ("a fresh replay store: nothing seen yet") and it's just a verification tool. Not a vuln.

**`Sign()` writes feed.sig next to feed with no OutsideGit check on the feed** — sig in repo is fine (public). OK.

Let me also double check `Known()` usage in `verify`: `["verify", var feed, .. var o] when Known(o, "--pub", "--kid", "--channel")` — OK.

And the catch: `catch (Exception e) when (...)` — exceptions not matching filter propagate → crash. E.g., `OutOfMemoryException`, `IndexOutOfRange` (the Opt bug), `UnauthorizedAccessException` is included... `Path.GetFullPath` on invalid chars → ArgumentException (included in .NET Core? NotSupportedException in old; modern → ArgumentException? Actually invalid path chars throw ArgumentException in .NET Core 2.1+... hmm, NotSupportedException was old framework). Minor robustness, skip.

Now write the report. Format per instructions: ID, TITLE, FILE+location, SEVERITY, CATEGORY, DESCRIPTION, ATTACK SCENARIO, CONFIDENCE, RECOMMENDED FIX.

Findings:
- S1: Unprotected named IPC objects enable protocol spoofing/squatting (Medium, High confidence).
- S2: HLSL injection via untrusted DXBC semantic names (Low, High confidence it exists / Low exploitability).
- S3: OutsideGit() safety rail depends on git from PATH/env (Low, Medium).

Should I include the `Opt()` index-out-of-range crash? It's a local CLI robustness bug, no security impact beyond crashing a signing tool with admin-typed args. Per "do not pad", skip — or mention briefly in observations? I'll skip; it's not security.

Should the empty-workdir `work.back()` UB be reported? Crash on empty arg — local robustness, no attacker path (Core invokes). Skip.

Let me reconsider whether there are any High/Critical findings I'm missing... The supplied code is mostly the warm host and D3D11 replay — both handle untrusted data carefully. The DXBC parsing is bounds-checked throughout. The genuinely security-critical code (FeedTrust, proxy db parsing, update download) is absent. So a short, honest list is correct.

Wait — one more careful look at `chunk()`:

```cpp
static std::string_view chunk(std::string_view c, const char* fourcc) {
    if (c.size() < 32 || c.substr(0, 4) != "DXBC") return {};
    for (uint32_t i = 0, n = u32(c, 28); i < n && i < 64; ++i) {
        size_t o = u32(c, 32 + 4 * i), len = u32(c, o + 4);
        if (o + 8 + len <= c.size() && !memcmp(c.data() + o, fourcc, 4)) return c.substr(o + 8, len);
    }
    return {};
}
```
`u32(c, o+4)`: if o is huge (0xFFFFFFFF), o+4 = 0x100000003 > size → returns 0 → len=0 → check `o+8 <= c.size()` fails → skip. Safe. If o valid but o+4 read gives attacker len — checked. memcmp 4 bytes at c.data()+o requires o+8+len ≤ size and len≥0 → o+8 ≤ size → o+4 ≤ size-4 → memcmp reads o..o+3 within bounds. Safe.

`signature()` — `std::string(d.data() + name, strnlen(d.data() + name, d.size() - name))` — name < d.size() checked → strnlen max = d.size()-name ≥ 1... if name points at last byte non-NUL → strnlen returns 1 → string of 1 char. Safe.

`parse()` — `if (t[p] >> 31) while (q < end && t[q++] >> 31) {}` — opcode extended tokens: q starts p+1. Then operand token skip. For OP_CUSTOMDATA, n = t[p+1] (dword count includes the 2 header dwords? custom data: token0 = opcode with length in next dword). If n is huge → `p + n > nt` → break. Safe.

One more: `s.type = t[0] >> 16` — then in warm11_item `program_type[stage]` compare — covered.

`partner_vs` — `regs` max 32 (e.reg < 32 guard). `pads`/`fields` unbounded-ish but bounded by 32 regs * 4. Fine.

`hlsl_type` — minp values map; fine.

`lines_up` — fine.

OK also `Dev11::views` keyed cache — analyzed, no security impact.

`warm11_drain` — `sev[k.first]` in warm11_close: `k.first` is Severity — filtered `m->Severity > WARNING continue` → severity ∈ {CORRUPTION=0, ERROR=1, WARNING=2} → sev[0..2] — array has 3 entries. Safe (message severity from debug layer is trusted-ish anyway).

Alright. Also consider reporting the **lack of `ERROR_ALREADY_EXISTS` check on CreateFileMappingW/CreateEventW** as part of S1 — yes, folded in.

Let me reconsider S1 severity once more. Concrete impacts:
1. Attacker connects to pipe first → injects arbitrary JSON lines → Core parser sees forged events (done/retry/progress with attacker-controlled numbers and the `crashed`/`isolate` arrays... wait those come from child's emit, but attacker writes raw lines directly). If Core's parser has any flaw (unverified), amplifier. Also forged "stage" event path? The stage event is emitted by parent before pipes. Attacker lines could include {"event":"done",...} → Core reports success → user misled; or {"event":"retry"} → triggers retries with attacker-chosen skip lists? The retry flow: Core spawns new warm with --skip/--isolate from the retry JSON — attacker-controlled retry JSON → attacker influences subsequent command-line args of the next warm process (numbers only, validated by parse()). Limited.
2. Pre-squatting PID-named objects → DoS or watchdog defeat.
3. Beat manipulation → pause/run confusion → DoS.
All same-user. Medium feels right, arguably Low. I'll go Medium with explicit reasoning, since integrity of a security-relevant protocol channel is violated without any attempt at protection, and the fix is cheap.

Actually — one nuance: pipes are `\\.\pipe\` (machine-wide namespace, not session). A *remote* attacker? Named pipes can be accessed remotely if the pipe's DACL allows and SMB is exposed. Default DACL on named pipes: grants... default security descriptor gives full control to creator/owner, SYSTEM, and **Everyone: read**? The default for CreateNamedPipe with NULL SD: the pipe gets a default DACL from the creator's token — typically Owner: Full, SYSTEM: Full, Everyone: Read? Hmm, for pipes the default DACL historically grants Everyone read access and anonymous... Actually Windows named pipes default DACL: `Everyone: GENERIC_READ`, `Anonymous: ...`? There have been CVEs about this. With default SD, remote users may be able to connect (read? write?). GENERIC_WRITE for clients requires write permission. Default pipe DACL (from the object manager for NamedPipe objects): grants Full Control to LocalSystem and Creator Owner, and Read to Everyone — I recall that clients need FILE_WRITE_DATA to write; Everyone gets GENERIC_READ | GENERIC_WRITE? Let me not overclaim: Microsoft's guidance is that NULL SD on pipes is dangerous; there have been EoP bugs via remote pipe connections. To be rigorous: I'll state that NULL DACL at minimum exposes to same-user/local processes, and possibly remote depending on the effective default DACL — recommend explicit SD + PIPE_REJECT_REMOTE_CLIENTS... Actually there's a simpler flag: `PIPE_REJECT_REMOTE_CLIENTS` in pipe mode? It's a flag for CreateNamedPipe (PIPE_REJECT_REMOTE_CLIENTS = 0x8) — yes, in the pipe mode parameter. Recommend that.

Given possible remote exposure of the pipe (write to the relay → forge JSON into Core), I could justify High... but the default DACL details are uncertain from the code alone. I'll keep Medium and note the remote-possibility explicitly as part of the finding with the fix (explicit DACL + PIPE_REJECT_REMOTE_CLIENTS).

Structure the report now. Also include a short "scope note" that critical update-feed/proxy code wasn't supplied.

Format: fields exactly as requested. Then UNVERIFIED OBSERVATIONS with needed files. Prioritize by severity. No padding.