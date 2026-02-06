# Shai-Hulud Scanner

Detect and clean the **Shai-Hulud supply chain attack** — a self-replicating worm targeting the JavaScript/Node.js ecosystem since September 2025, affecting 25,000+ repositories.

## Tools

| Tool | Language | Approach | What it does |
|------|----------|----------|-------------|
| [**sandtrace**](#sandtrace--malware-sandbox-with-syscall-tracing) | Rust | Dynamic (runtime sandbox) | Run suspicious binaries in an 8-layer sandbox, trace every syscall, log to JSONL |
| [**sandworm**](#sandworm--rust-filesystem-scanner) | Rust | Static (filesystem sweep) | Fast parallel scan for whitespace obfuscation across entire directory trees |
| [**detect-config-malware.sh**](#detect-config-malwaresh--git-repo-scanner) | Bash | Static (git history) | 7-phase deep audit of git repos across all branches with cleanup mode |
| [**purge-malware-from-history.sh**](#purge-malware-from-historysh--git-history-rewriter) | Bash | Git rewrite | Strip malware payloads from every commit in git history |
| [**scan-all-repos.sh**](#scan-all-repossh--multi-repo-orchestration) | Bash | Multi-repo orchestration | Auto-discover and scan all your GitHub repos |

**Recommended workflow:** sandworm for fast triage, bash scanner for deep git audit, sandtrace to safely execute and analyze anything flagged.

---

## What Is Shai-Hulud?

Shai-Hulud is a supply chain attack that injects malicious code into JavaScript/TypeScript config files (vite.config.js, tailwind.config.ts, etc.) using whitespace obfuscation — hiding payloads off-screen behind thousands of spaces. Once executed, it:

- **Steals credentials** — environment variables, cloud tokens (AWS, Azure, GCP), CI/CD secrets
- **Exfiltrates via webhooks** — sends stolen data to webhook.site endpoints
- **Registers rogue GitHub Actions runners** — named `SHA1HULUD`, giving attackers CI/CD access
- **Installs TruffleHog** — scans your entire filesystem for additional secrets
- **Self-replicates** — infects other config files in the same repo and spreads to dependencies

---

## sandtrace — Malware Sandbox with Syscall Tracing

<p align="center">
  <img src="sandtrace/logo.svg" alt="sandtrace logo" width="320">
  <br>
  <em>No escape without a trace.</em>
</p>

`sandtrace` is a Rust-based malware sandbox that combines ptrace syscall tracing, Landlock filesystem restriction, seccomp-bpf syscall filtering, and Linux namespaces for safely analyzing untrusted binaries. It provides structured JSONL output and colored terminal display.

While sandworm detects malware signatures on disk and the bash scanner audits git history, sandtrace takes the next step: **run the suspicious binary and observe exactly what it does** — every file it opens, every network connection it attempts, every process it spawns — all within an isolated sandbox that prevents real damage.

### Security Layers

sandtrace applies 8 independent defense-in-depth layers:

| Layer | Protection |
|-------|-----------|
| User namespace | UID/GID isolation |
| Mount namespace | Minimal filesystem (tmpfs /tmp, private /dev, remounted /proc) |
| PID namespace | Host process hiding |
| IPC/UTS/Cgroup namespaces | Full isolation from host IPC, hostname, cgroups |
| Network namespace | No network by default (loopback only) |
| Landlock LSM | Kernel-level filesystem access control |
| seccomp-bpf | Dangerous syscall blocking + W^X enforcement |
| ptrace | Real-time syscall tracing and policy enforcement |
| rlimits | Resource limits (max processes, file size, open files) |

### Build

```bash
cd sandtrace
cargo build --release
# Binary: sandtrace/target/release/sandtrace (2.3MB static binary)
```

### Usage

```bash
# Trace what a binary does (no enforcement, just observe)
./sandtrace/target/release/sandtrace run --trace-only -vv ./suspicious_binary

# Full sandbox — deny everything except standard libraries
./sandtrace/target/release/sandtrace run ./suspicious_binary

# Allow network + specific paths, log to file
./sandtrace/target/release/sandtrace run --allow-net --allow-path ./project -o trace.jsonl npm install

# Use a custom policy file
./sandtrace/target/release/sandtrace run --policy sandtrace/examples/strict.toml ./untrusted_elf

# Audit npm install with tailored policy
./sandtrace/target/release/sandtrace run --policy sandtrace/examples/npm_audit.toml npm install
```

### JSONL Output

Every syscall is logged as structured JSON, parseable by `jq`, Python, or any SIEM:

```json
{"event_type":"syscall","pid":12345,"syscall":"openat","args":{"decoded":{"path":"/home/user/.ssh/id_rsa","flags":"O_RDONLY"}},"action":"deny","return_value":-1}
```

A summary is emitted at the end of each trace:

```json
{
  "event_type": "summary",
  "total_syscalls": 4523,
  "denied_count": 3,
  "files_accessed": ["/etc/passwd", "/usr/lib/libnode.so"],
  "files_created": ["/tmp/payload.bin"],
  "files_deleted": [],
  "network_attempts": ["connect 93.184.216.34:443"],
  "suspicious_activity": ["Attempted to read /home/user/.ssh/id_rsa"]
}
```

### Policy Files (TOML)

Five example policies are included in `sandtrace/examples/`:

| Policy | Use Case |
|--------|----------|
| `strict.toml` | Maximum lockdown — read-only standard libs, no network, no exec |
| `permissive.toml` | Observe everything, block only truly dangerous syscalls |
| `npm_audit.toml` | Audit `npm install` — allow network + node_modules writes, deny SSH/env access |
| `pnpm_audit.toml` | Audit `pnpm install` — same as npm but with pnpm paths/lockfile |
| `composer_audit.toml` | Audit `composer install` — allow network + vendor writes, permit php/git exec |

See [sandtrace/README.md](sandtrace/README.md) for full CLI reference, package manager auditing examples, and security architecture details.

---

## sandworm — Rust Filesystem Scanner

<p align="center">
  <img src="sandworm/logo.svg" alt="sandworm logo" width="320">
  <br>
  <em>The worm finds what hides.</em>
</p>

`sandworm` is a fast, parallel Rust tool that scans entire filesystems for whitespace obfuscation — the signature technique used by Shai-Hulud to hide malicious payloads off-screen behind thousands of spaces.

While the bash scripts above are git-aware and scan repositories branch-by-branch, sandworm takes a different approach: it sweeps every file under a directory tree (defaulting to `$HOME`), flagging any file with abnormally long runs of consecutive whitespace. This makes it useful for catching infections outside of git repos — in `node_modules`, build artifacts, cached files, or anywhere malware might land.

### Build

```bash
cd sandworm
cargo build --release
# Binary: sandworm/target/release/sandworm
```

### Usage

```bash
# Scan home directory (default, 50+ whitespace chars)
./sandworm/target/release/sandworm

# Scan a specific directory
./sandworm/target/release/sandworm /path/to/project

# Raise threshold to reduce noise (1000+ chars catches real obfuscation)
./sandworm/target/release/sandworm -n 1000

# Show line previews for each finding
./sandworm/target/release/sandworm -n 1000 -v

# Custom max file size (default 10MB)
./sandworm/target/release/sandworm --max-size 50000000
```

### Performance

sandworm uses [rayon](https://docs.rs/rayon) for parallel file scanning and the [ignore](https://docs.rs/ignore) crate for fast directory traversal. It skips `node_modules`, `.git`, `vendor`, and other junk directories automatically. Typical performance: **440,000+ files in ~1-2 seconds**.

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

### GitHub Actions Workflow

A lightweight GitHub Actions workflow is included for server-side enforcement. It runs on pull requests and pushes to protected branches, checking for:

1. Config file size (>5KB)
2. Long lines (>500 chars) in JS/TS config files
3. Whitespace obfuscation (50+ consecutive spaces)
4. Malware signatures (strain markers, eval+atob, global['_V'], require hijacking, payload references, behavioral indicators)

#### Install on a repo

Copy the workflow file to your repo:

```bash
mkdir -p .github/workflows
cp /path/to/shai-hulud-scanner/.github/workflows/shai-hulud-scan.yml .github/workflows/
git add .github/workflows/shai-hulud-scan.yml
git commit -m "ci: add Shai-Hulud supply chain security scan"
git push
```

#### Install across an entire GitHub org

Use the GitHub Contents API to push the workflow to all repos at once:

```bash
CONTENT=$(base64 -w 0 .github/workflows/shai-hulud-scan.yml)
gh api --method PUT "repos/YOUR_ORG/REPO_NAME/contents/.github/workflows/shai-hulud-scan.yml" \
  -f message="ci: add Shai-Hulud supply chain security scan" \
  -f content="$CONTENT" \
  -f branch="main"
```

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
| `sandtrace/` | Rust malware sandbox — syscall tracing + enforcement with 8-layer isolation |
| `sandworm/` | Rust filesystem scanner — fast parallel whitespace obfuscation detection |
| `detect-config-malware.sh` | Core scanner — single repo, 7-phase detection + cleanup mode |
| `purge-malware-from-history.sh` | Rewrite git history to remove embedded malware from all commits |
| `scan-all-repos.sh` | Multi-repo orchestrator with GitHub auto-discovery |
| `repos-to-scan.example.conf` | Example config for manual repo list (fallback mode) |
| `.github/workflows/shai-hulud-scan.yml` | GitHub Actions workflow for server-side enforcement |

## Contributing

If you discover new Shai-Hulud strains, payload hashes, or behavioral indicators, please open an issue or PR.

## License

MIT
