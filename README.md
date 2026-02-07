# Shai-Hulud Scanner

Detect and clean the **Shai-Hulud supply chain attack** — a self-replicating worm targeting the JavaScript/Node.js ecosystem since September 2025, affecting 25,000+ repositories.

## Tools

| Tool | Language | Approach | What it does |
|------|----------|----------|-------------|
| [**sandtrace**](https://github.com/diogee-games/sandtrace) | Rust | Dynamic (runtime sandbox) | Run suspicious binaries in an 8-layer sandbox, trace every syscall, log to JSONL |
| [**sandworm**](https://github.com/diogee-games/sandworm) | Rust | Static (filesystem sweep) | Fast parallel scan for whitespace obfuscation across entire directory trees |
| [**detect-config-malware.sh**](#detect-config-malwaresh--git-repo-scanner) | Bash | Static (git history) | 7-phase deep audit of git repos across all branches with cleanup mode |
| [**purge-malware-from-history.sh**](#purge-malware-from-historysh--git-history-rewriter) | Bash | Git rewrite | Strip malware payloads from every commit in git history |
| [**scan-all-repos.sh**](#scan-all-repossh--multi-repo-orchestration) | Bash | Multi-repo orchestration | Auto-discover and scan all your GitHub repos |
| [**shai-hulud-scan.yml**](#shai-hulud-scanyml--github-actions-workflow) | GitHub Actions | CI/CD gate | Block PRs and pushes containing malware signatures or whitespace obfuscation |

**Recommended workflow:** sandworm for fast triage, bash scanner for deep git audit, sandtrace to safely execute and analyze anything flagged. Add the GitHub Actions workflow to prevent reinfection via PRs.

---

## What Is Shai-Hulud?

Shai-Hulud is a supply chain attack that injects malicious code into JavaScript/TypeScript config files (vite.config.js, tailwind.config.ts, etc.) using whitespace obfuscation — hiding payloads off-screen behind thousands of spaces. Once executed, it:

- **Steals credentials** — environment variables, cloud tokens (AWS, Azure, GCP), CI/CD secrets
- **Exfiltrates via webhooks** — sends stolen data to webhook.site endpoints
- **Registers rogue GitHub Actions runners** — named `SHA1HULUD`, giving attackers CI/CD access
- **Installs TruffleHog** — scans your entire filesystem for additional secrets
- **Self-replicates** — infects other config files in the same repo and spreads to dependencies

---

## Companion Rust Tools

The Rust-based tools have been moved to their own repositories for independent development and releases:

### sandtrace — Malware Sandbox with Syscall Tracing

**Repo:** [github.com/diogee-games/sandtrace](https://github.com/diogee-games/sandtrace)

Rust-based malware sandbox combining ptrace syscall tracing, Landlock filesystem restriction, seccomp-bpf syscall filtering, and Linux namespaces. 8 independent defense-in-depth layers for safely analyzing untrusted binaries with structured JSONL output.

### sandworm — Rust Filesystem Scanner

**Repo:** [github.com/diogee-games/sandworm](https://github.com/diogee-games/sandworm)

Fast parallel filesystem scanner for whitespace obfuscation detection. Sweeps entire directory trees at 440,000+ files/sec using rayon, flagging files where malicious code hides behind thousands of spaces.

---

## detect-config-malware.sh — Git Repo Scanner

The core bash scanner — 7-phase deep audit of git repos across all branches with interactive cleanup mode.

### What It Detects

#### Phase 1: Malware Signatures
Known strain IDs embedded in payloads: `global.i='5-3-247'`, `'5-3-267'`, `'5-228'`, `'5-3-238'`, `'5-143'`, plus generic pattern matching for new strains. Also detects obfuscated variants:
- `eval(..atob(..))` — base64-encoded payload execution
- `global['_V']` — variant strain marker used to bypass `global.i` detection
- `global['r']=require` — require hijacking for module access
- Large base64 blobs (200+ chars) — encoded malware payloads

#### Phase 2: Whitespace Obfuscation
JS/TS files with 50+ consecutive spaces hiding code off-screen — the primary injection technique.

#### Phase 3: Suspicious Config Files
Config files over 8KB (typically <1KB), lines over 256 characters, hidden content via whitespace padding.

#### Phase 4: Known Payload Files
Known payload filenames (`setup_bun.js`, `bun_environment.js`, `set_bun.js`, `bundle.js`) with SHA256 hash verification against confirmed Shai-Hulud payloads.

#### Phase 5: Package.json Scripts
Suspicious `preinstall`/`postinstall`/`prepare` scripts that reference Bun installation, setup_bun, or execute node on unknown files.

#### Phase 6: Behavioral Indicators
Patterns indicating active compromise: TruffleHog execution, `SHA1HULUD` runner registration, webhook.site exfiltration URLs, Azure token harvesting, GitHub Actions runner downloads.

#### Phase 7: Large JS Files
Abnormally large JS files (>5MB) in non-build directories — Shai-Hulud payloads can be 9MB+.

### What Makes This Different

- **Scans ALL branches** — not just the working tree. Malware hides in feature branches, stale PRs, and abandoned branches
- **Auto-discovers repos** — uses the GitHub CLI to find every repo you have access to across all your orgs
- **Uses git object store** — `git grep` searches the object store directly, catching malware in any commit on any branch without checking out files
- **Interactive cleanup** — finds infected files, locates clean versions in git history, restores them, and guides you through force-pushing the fix
- **7-phase detection** — signatures, obfuscation, config analysis, known payloads, package.json scripts, behavioral indicators, and large file detection

### Prerequisites

- **bash** 4.0+
- **git**
- **python3** (for package.json script analysis)
- **sha256sum** (for payload hash verification)
- **gh** (GitHub CLI, optional) — for auto-discovery. Install: https://cli.github.com/

### Quick Start

```bash
# Clone the scanner
git clone https://github.com/diogee-games/shai-hulud-scanner.git
cd shai-hulud-scanner

# Make scripts executable
chmod +x detect-config-malware.sh scan-all-repos.sh

# Scan a single repo (all branches by default)
./detect-config-malware.sh /path/to/your/repo

# Scan all your GitHub repos (auto-discover)
./scan-all-repos.sh

# See what repos would be discovered
./scan-all-repos.sh --list
```

### Usage

#### Scan a single repo

```bash
# All branches (default)
./detect-config-malware.sh /path/to/repo

# Verbose output (shows every file scanned)
./detect-config-malware.sh /path/to/repo --verbose
```

#### Clean infected files

```bash
./detect-config-malware.sh /path/to/repo --cleanup
```

**WARNING: Cleanup mode rewrites git history.** It will:
1. Find infected files on the current branch
2. Search git history for the last clean version of each file
3. Restore the clean version to the working tree
4. Create a fix commit
5. Prompt you to force-push (overwrites remote history)

All developers must re-pull after cleanup. Commits made on top of infected history may need to be cherry-picked.

### How It Works

#### Branch scanning flow

1. `git fetch --all` to update remote-tracking branches
2. Enumerate all refs via `git for-each-ref refs/heads/ refs/remotes/`
3. `git grep` across all refs for malware signatures (single fast operation)
4. `git grep` for whitespace obfuscation patterns in JS/TS files
5. `git ls-tree -l -r` per ref to find config files with size analysis
6. `git ls-tree` + `sha256sum` for known payload file detection
7. Python-based `package.json` script extraction and pattern matching
8. `git grep` for behavioral indicators across all file types
9. `git ls-tree -l` for large JS file detection with hash verification

---

## purge-malware-from-history.sh — Git History Rewriter

Removes Shai-Hulud malware payloads from **every commit in git history** using `git-filter-repo`. The malware hides after legitimate code on a line, separated by 50+ spaces — this script strips the payload while preserving the clean code.

```bash
# Dry-run: show what would change
./purge-malware-from-history.sh /path/to/infected-repo

# Actually rewrite history
./purge-malware-from-history.sh /path/to/infected-repo --execute
```

Requires `git-filter-repo` (`pip3 install git-filter-repo`). Creates a tar backup before rewriting, restores remotes after, verifies with the scanner, and prompts for force-push.

---

## scan-all-repos.sh — Multi-Repo Orchestration

Auto-discover and scan all your GitHub repos using the GitHub CLI.

```bash
# Interactive — prompts to clone repos not found locally
./scan-all-repos.sh

# Auto-clone missing repos to ~/repos-scan/
./scan-all-repos.sh --auto-clone

# Scan specific repos only
./scan-all-repos.sh /path/to/repo1 /path/to/repo2

# List discovered repos and their local status
./scan-all-repos.sh --list
```

### Configuration

Edit the top of `scan-all-repos.sh` to customize:

```bash
# Your GitHub username
GH_USER="your-username"

# Orgs to include
INCLUDE_ORGS=("my-company" "my-other-org")

# Regex pattern for orgs to skip
SKIP_ORGS_PATTERN="^SomePrefix"

# Exact org names to skip (e.g. SAML-protected orgs)
SKIP_ORGS_EXACT=("saml-protected-org")
```

### Fallback mode

If `gh` CLI is not available, the scanner reads from `repos-to-scan.conf`:

```
# Format: LOCAL_PATH | GITHUB_ORG/REPO | DESCRIPTION
/home/user/my-app | myorg/my-app | Main application
/home/user/api    | myorg/api    | API service
```

Copy `repos-to-scan.example.conf` to `repos-to-scan.conf` and edit to match your setup.

### Repo discovery flow

1. `gh repo list` for personal repos
2. `gh repo list <org>` for each included org
3. `gh api user/orgs` to discover additional orgs, filtered by skip patterns
4. Deduplicate and sort
5. Map to local paths or clone to `~/repos-scan/`

---

## shai-hulud-scan.yml — GitHub Actions Workflow

A drop-in GitHub Actions workflow that blocks PRs and pushes containing Shai-Hulud malware. Runs all 7 detection phases from the bash scanner — no dependencies, no external actions, runs in under 30 seconds.

### What It Checks

| Phase | What it catches |
|-------|----------------|
| 1. Malware signatures | 5 known strains (`global.i=`), generic catch-all, `eval+atob`, `eval+global[`, `global['_V']`, require hijacking, large base64 blobs (200+ chars) |
| 2. Whitespace obfuscation | 50+ consecutive spaces hiding code off-screen in JS/TS files |
| 3. Config file analysis | Config files over 8KB, lines over 256 chars (thresholds match bash scanner) |
| 4. Known payload files | `setup_bun.js`, `bun_environment.js`, `set_bun.js`, `bundle.js` with SHA256 hash verification against 5 confirmed payloads |
| 5. Package.json scripts | `preinstall`/`postinstall`/`prepare`/`prepublish`/`prepack` hooks referencing `setup_bun`, `bun.sh/install`, `curl.*bun.sh`; lifecycle scripts running `node` directly |
| 6. Behavioral indicators | `trufflehog filesystem`, `SHA1HULUD`/`SHA1Hulud`/`Sha1-Hulud`, `webhook.site`, Actions runner download/registration, Azure token theft (`az account get-access-token`, `azd auth token`) |
| 7. Large JS files | JS/TS files over 5MB (Shai-Hulud payloads can be 9MB+) with SHA256 verification |

### Triggers

Runs on:
- **All pull requests** (any branch)
- **Pushes** to `main`, `master`, `stage`, `staging`, `production`, `develop`

### Install on a repo

```bash
mkdir -p .github/workflows
cp /path/to/shai-hulud-scanner/.github/workflows/shai-hulud-scan.yml .github/workflows/
git add .github/workflows/shai-hulud-scan.yml
git commit -m "ci: add Shai-Hulud supply chain security scan"
git push
```

Or copy the file directly from this repo's `.github/workflows/shai-hulud-scan.yml`.

### Install across an entire GitHub org

Use the GitHub Contents API to push the workflow to all repos at once:

```bash
CONTENT=$(base64 -w 0 .github/workflows/shai-hulud-scan.yml)

# Repeat for each repo, or loop over `gh repo list --json name -q '.[].name'`
gh api --method PUT "repos/YOUR_ORG/REPO_NAME/contents/.github/workflows/shai-hulud-scan.yml" \
  -f message="ci: add Shai-Hulud supply chain security scan" \
  -f content="$CONTENT" \
  -f branch="main"
```

---

## Reference

### Known Shai-Hulud Strains

| Strain | Notes |
|--------|-------|
| 5-3-247 | Wave 1 — original strain |
| 5-228 | Wave 1 variant |
| 5-3-238 | Wave 1 variant |
| 5-3-267 | Wave 2 — re-infection during cleanup |
| 5-143 | Later discovery |

#### Obfuscation Variants

Newer payloads avoid direct `global.i=` by using:
- `eval("global['_V']='5-3-238';"+atob('...'))` — strain marker inside eval, payload base64-encoded
- Hundreds of spaces after legitimate code to push the payload off-screen
- `global['r']=require` to hijack the require function without a searchable pattern

### Known Payload Hashes (SHA256)

| Hash | File |
|------|------|
| `46faab8a...` | bundle.js |
| `62ee164b...` | bun_environment.js v1 |
| `f099c5d9...` | bun_environment.js v2 |
| `cbb9bc5a...` | bun_environment.js v3 |
| `a3894003...` | setup_bun.js |

### What To Do If Infected

1. **Stop all pushes** — notify your team immediately
2. **Run the cleanup**: `./detect-config-malware.sh /path/to/repo --cleanup`
3. **Rotate ALL credentials** — every secret in your environment, CI/CD, cloud providers
4. **Check GitHub Actions** — look for rogue self-hosted runners named `SHA1HULUD`
5. **Audit webhook.site** — check if any exfiltration occurred
6. **Review package.json** — check for suspicious preinstall/postinstall scripts
7. **Re-scan after cleanup** to verify

---

## Files

| File | Purpose |
|------|---------|
| `detect-config-malware.sh` | Core scanner — single repo, 7-phase detection + cleanup mode |
| `purge-malware-from-history.sh` | Rewrite git history to remove embedded malware from all commits |
| `scan-all-repos.sh` | Multi-repo orchestrator with GitHub auto-discovery |
| `.github/workflows/shai-hulud-scan.yml` | GitHub Actions workflow — drop into any repo to block malware PRs |
| `repos-to-scan.example.conf` | Example config for manual repo list (fallback mode) |

## Related Repositories

| Repo | Description |
|------|-------------|
| [sandtrace](https://github.com/diogee-games/sandtrace) | Rust malware sandbox — syscall tracing + enforcement with 8-layer isolation |
| [sandworm](https://github.com/diogee-games/sandworm) | Rust filesystem scanner — fast parallel whitespace obfuscation detection |

## Contributing

If you discover new Shai-Hulud strains, payload hashes, or behavioral indicators, please open an issue or PR.

## License

MIT
