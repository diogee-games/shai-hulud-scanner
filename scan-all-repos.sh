#!/bin/bash
#
# Scan multiple repositories for config file malware
# Auto-discovers GitHub repos via gh CLI, scans all branches
#
# Usage:
#   ./scan-all-repos.sh                    # Discover & scan all repos (all branches)
#   ./scan-all-repos.sh /path/to/repo      # Scan specific repo(s)
#   ./scan-all-repos.sh --list             # List discovered repos and local status
#   ./scan-all-repos.sh --auto-clone       # Clone missing repos without prompting
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECT_SCRIPT="$SCRIPT_DIR/detect-config-malware.sh"
CONFIG_FILE="$SCRIPT_DIR/repos-to-scan.conf"
CLONE_BASE="$HOME/repos-scan"

# GitHub username — auto-detected from gh auth if empty
GH_USER=""

# Orgs to explicitly include in scanning
INCLUDE_ORGS=()

# Regex pattern for orgs to skip (e.g. "^Kaseya" skips all Kaseya* orgs)
SKIP_ORGS_PATTERN=""

# Exact org names to skip (e.g. SAML-protected orgs you can't clone from)
SKIP_ORGS_EXACT=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TOTAL_ISSUES=0
TOTAL_SCANNED=0
TOTAL_SKIPPED=0
AUTO_CLONE=false

# Check if gh CLI is available and authenticated
check_gh() {
    if ! command -v gh &>/dev/null; then
        echo -e "${RED}Error: gh CLI not installed. Install from https://cli.github.com/${NC}" >&2
        exit 1
    fi

    if ! gh auth status &>/dev/null 2>&1; then
        echo -e "${RED}Error: gh CLI not authenticated. Run 'gh auth login' first.${NC}" >&2
        exit 1
    fi
}

# Check if an org should be skipped
should_skip_org() {
    local org="$1"

    # Check skip pattern
    if [[ -n "$SKIP_ORGS_PATTERN" ]] && [[ "$org" =~ $SKIP_ORGS_PATTERN ]]; then
        return 0
    fi

    # Check exact skip list
    for skip_org in "${SKIP_ORGS_EXACT[@]+"${SKIP_ORGS_EXACT[@]}"}"; do
        if [[ "$org" == "$skip_org" ]]; then
            return 0
        fi
    done

    return 1
}

# Discover all repos the user has access to
# Returns lines of: owner/repo
discover_repos() {
    local all_repos=()

    # Auto-detect GH_USER if not set
    if [[ -z "$GH_USER" ]]; then
        GH_USER=$(gh api user --jq '.login' 2>/dev/null || true)
        if [[ -z "$GH_USER" ]]; then
            echo -e "${RED}Error: Could not detect GitHub username. Set GH_USER in script or run 'gh auth login'.${NC}" >&2
            return 1
        fi
    fi

    echo -e "${BLUE}Discovering GitHub repositories...${NC}" >&2

    # 1. Personal repos
    echo -e "  Fetching repos for ${CYAN}${GH_USER}${NC}..." >&2
    while IFS= read -r repo; do
        [[ -n "$repo" ]] && all_repos+=("$repo")
    done < <(gh repo list "$GH_USER" --limit 500 --json nameWithOwner -q '.[].nameWithOwner' 2>/dev/null || true)
    echo -e "    Found ${#all_repos[@]} personal repos" >&2

    # 2. Org repos from include list
    for org in "${INCLUDE_ORGS[@]+"${INCLUDE_ORGS[@]}"}"; do
        if should_skip_org "$org"; then
            echo -e "  Skipping org: ${YELLOW}${org}${NC}" >&2
            continue
        fi

        echo -e "  Fetching repos for org ${CYAN}${org}${NC}..." >&2
        local org_count=0
        while IFS= read -r repo; do
            if [[ -n "$repo" ]]; then
                all_repos+=("$repo")
                ((org_count++))
            fi
        done < <(gh repo list "$org" --limit 500 --json nameWithOwner -q '.[].nameWithOwner' 2>/dev/null || true)
        echo -e "    Found ${org_count} repos" >&2
    done

    # 3. Also discover orgs dynamically and filter
    echo -e "  Checking for additional orgs..." >&2
    while IFS= read -r org; do
        [[ -z "$org" ]] && continue

        # Skip if already in include list
        local already_included=false
        for inc_org in "${INCLUDE_ORGS[@]+"${INCLUDE_ORGS[@]}"}"; do
            if [[ "$org" == "$inc_org" ]]; then
                already_included=true
                break
            fi
        done
        [[ "$already_included" == true ]] && continue

        if should_skip_org "$org"; then
            echo -e "  Skipping org: ${YELLOW}${org}${NC} (filtered)" >&2
            continue
        fi

        echo -e "  Fetching repos for discovered org ${CYAN}${org}${NC}..." >&2
        local org_count=0
        while IFS= read -r repo; do
            if [[ -n "$repo" ]]; then
                all_repos+=("$repo")
                ((org_count++))
            fi
        done < <(gh repo list "$org" --limit 500 --json nameWithOwner -q '.[].nameWithOwner' 2>/dev/null || true)
        echo -e "    Found ${org_count} repos" >&2
    done < <(gh api user/orgs --jq '.[].login' 2>/dev/null || true)

    # Deduplicate
    printf '%s\n' "${all_repos[@]}" | sort -u
}

# Find local path for a GitHub repo
# Returns the path if found, empty string if not
find_local_repo() {
    local gh_repo="$1"  # e.g. "uglydawg/myrepo"
    local owner="${gh_repo%%/*}"
    local name="${gh_repo##*/}"

    # Check config file for explicit path mapping first
    if [[ -f "$CONFIG_FILE" ]]; then
        while IFS='|' read -r local_path repo_name _; do
            local_path=$(echo "$local_path" | xargs)
            repo_name=$(echo "$repo_name" | xargs)
            if [[ "$repo_name" == "$gh_repo" ]] && [[ -d "$local_path/.git" ]]; then
                echo "$local_path"
                return 0
            fi
        done < <(grep -v '^#' "$CONFIG_FILE" | grep -v '^$')
    fi

    # Check common locations
    local candidates=(
        "$HOME/$name"
        "$HOME/repos-scan/$owner/$name"
        "$HOME/repos-scan/$name"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -d "$candidate/.git" ]]; then
            # Verify it's the right repo by checking remote URL
            local remote_url
            remote_url=$(git -C "$candidate" remote get-url origin 2>/dev/null || true)
            if [[ "$remote_url" == *"$gh_repo"* ]] || [[ "$remote_url" == *"$name"* ]]; then
                echo "$candidate"
                return 0
            fi
        fi
    done

    return 1
}

# Clone a repo to ~/repos-scan/owner/name/
clone_repo() {
    local gh_repo="$1"  # e.g. "uglydawg/myrepo"
    local owner="${gh_repo%%/*}"
    local name="${gh_repo##*/}"
    local clone_dir="$CLONE_BASE/$owner/$name"

    if [[ -d "$clone_dir" ]]; then
        echo "$clone_dir"
        return 0
    fi

    mkdir -p "$CLONE_BASE/$owner"
    echo -e "  Cloning ${CYAN}${gh_repo}${NC} to ${clone_dir}..." >&2
    if gh repo clone "$gh_repo" "$clone_dir" -- --quiet 2>/dev/null; then
        echo "$clone_dir"
        return 0
    else
        echo -e "  ${RED}Failed to clone ${gh_repo}${NC}" >&2
        return 1
    fi
}

# Prompt user to clone a missing repo (or auto-clone)
prompt_clone() {
    local gh_repo="$1"

    if [[ "$AUTO_CLONE" == true ]]; then
        clone_repo "$gh_repo"
        return $?
    fi

    echo -en "  ${YELLOW}Repo not found locally:${NC} ${gh_repo}. Clone to ~/repos-scan/? [y/N/a(ll)] " >&2
    read -r answer </dev/tty
    case "$answer" in
        y|Y)
            clone_repo "$gh_repo"
            return $?
            ;;
        a|A)
            AUTO_CLONE=true
            clone_repo "$gh_repo"
            return $?
            ;;
        *)
            echo -e "  Skipping ${gh_repo}" >&2
            return 1
            ;;
    esac
}

# List discovered repos and their local status
list_repos() {
    check_gh

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            GitHub Repository Discovery                       ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local repos
    repos=$(discover_repos)
    local total=0
    local found=0
    local missing=0

    echo ""
    printf "%-45s %-40s %s\n" "GITHUB REPO" "LOCAL PATH" "STATUS"
    echo "──────────────────────────────────────────────────────────────────────────────────────────────────────────"

    while IFS= read -r gh_repo; do
        [[ -z "$gh_repo" ]] && continue
        ((total++))

        local local_path
        local_path=$(find_local_repo "$gh_repo" 2>/dev/null) || local_path=""

        if [[ -n "$local_path" ]]; then
            printf "%-45s %-40s %b\n" "$gh_repo" "$local_path" "${GREEN}✓ found${NC}"
            ((found++))
        else
            printf "%-45s %-40s %b\n" "$gh_repo" "-" "${YELLOW}✗ not cloned${NC}"
            ((missing++))
        fi
    done <<< "$repos"

    echo ""
    echo -e "Total: ${total}  |  ${GREEN}Found locally: ${found}${NC}  |  ${YELLOW}Not cloned: ${missing}${NC}"
    echo ""
}

print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              Multi-Repository Malware Scan                   ║${NC}"
    echo -e "${BLUE}║           Shai-Hulud Detection (All Branches)                ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

scan_repo() {
    local repo="$1"
    local gh_name="${2:-}"

    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"

    if [[ -d "$repo" ]]; then
        local label="$repo"
        [[ -n "$gh_name" ]] && label="$gh_name ($repo)"
        echo -e "Scanning: ${GREEN}${label}${NC}"
        echo ""
        ((TOTAL_SCANNED++)) || true

        if "$DETECT_SCRIPT" "$repo" --all-branches; then
            echo -e "${GREEN}✓ Clean${NC}"
        else
            echo -e "${RED}✗ Issues detected${NC}"
            ((TOTAL_ISSUES++)) || true
        fi
    else
        echo -e "${YELLOW}Skipping (not found): $repo${NC}"
        ((TOTAL_SKIPPED++)) || true
    fi

    echo ""
}

print_summary() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                      FINAL RESULTS                             ${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Repositories scanned: $TOTAL_SCANNED"
    echo "Repositories skipped: $TOTAL_SKIPPED"
    echo ""

    if [[ "$TOTAL_ISSUES" -eq 0 ]]; then
        echo -e "${GREEN}All scanned repositories clean!${NC}"
    else
        echo -e "${RED}$TOTAL_ISSUES repository/repositories with potential issues${NC}"
        echo ""
        echo "Review the output above for details."
    fi
}

main() {
    # Handle --list flag
    if [[ "${1:-}" == "--list" ]]; then
        list_repos
        exit 0
    fi

    # Handle --help flag
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: $0 [OPTIONS] [REPO_PATHS...]"
        echo ""
        echo "Options:"
        echo "  --list         List discovered GitHub repos and their local status"
        echo "  --auto-clone   Clone missing repos automatically (no prompts)"
        echo "  --help         Show this help message"
        echo ""
        echo "If no paths provided, auto-discovers repos via GitHub API."
        echo "Falls back to $CONFIG_FILE if gh CLI is unavailable."
        exit 0
    fi

    # Check for --auto-clone flag
    local positional_args=()
    for arg in "$@"; do
        case "$arg" in
            --auto-clone) AUTO_CLONE=true ;;
            *) positional_args+=("$arg") ;;
        esac
    done

    print_header

    # If explicit paths provided, scan those directly
    if [[ ${#positional_args[@]} -gt 0 ]]; then
        for repo in "${positional_args[@]}"; do
            scan_repo "$repo"
        done
        print_summary
        [[ "$TOTAL_ISSUES" -gt 0 ]] && exit 1
        exit 0
    fi

    # Auto-discover via GitHub API
    if command -v gh &>/dev/null && gh auth status &>/dev/null 2>&1; then
        check_gh

        local repos
        repos=$(discover_repos)
        echo ""

        while IFS= read -r gh_repo; do
            [[ -z "$gh_repo" ]] && continue

            local local_path
            local_path=$(find_local_repo "$gh_repo" 2>/dev/null) || local_path=""

            if [[ -n "$local_path" ]]; then
                scan_repo "$local_path" "$gh_repo"
            else
                # Repo not found locally - prompt to clone
                local cloned_path
                cloned_path=$(prompt_clone "$gh_repo" 2>/dev/null) || cloned_path=""
                if [[ -n "$cloned_path" ]]; then
                    scan_repo "$cloned_path" "$gh_repo"
                else
                    echo -e "${YELLOW}Skipping: ${gh_repo} (not cloned)${NC}"
                    ((TOTAL_SKIPPED++)) || true
                    echo ""
                fi
            fi
        done <<< "$repos"
    else
        # Fallback to config file
        echo -e "${YELLOW}gh CLI not available, falling back to config file: $CONFIG_FILE${NC}"
        echo ""

        while IFS= read -r repo; do
            [[ -n "$repo" ]] && scan_repo "$repo"
        done < <(
            if [[ -f "$CONFIG_FILE" ]]; then
                while IFS= read -r line; do
                    [[ "$line" =~ ^[[:space:]]*# ]] && continue
                    [[ -z "${line// }" ]] && continue
                    local path="${line%%|*}"
                    path="${path// /}"
                    [[ -n "$path" ]] && echo "$path"
                done < "$CONFIG_FILE"
            else
                echo -e "${RED}Config file not found: $CONFIG_FILE${NC}" >&2
            fi
        )
    fi

    print_summary

    [[ "$TOTAL_ISSUES" -gt 0 ]] && exit 1
    exit 0
}

main "$@"
