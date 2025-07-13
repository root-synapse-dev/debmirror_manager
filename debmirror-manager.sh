#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL DEBIAN/UBUNTU MIRROR MANAGER
#═══════════════════════════════════════════════════════════════════════════════
# Script:      mirror-manager
# Version:     2.9.0 (Definitive LTS Resolution Fix)
# Author:      Synapse Dev Ω (Powered with AI) & User Collaboration
# License:     MIT
# Description: Enterprise-grade Debian & Ubuntu repository mirror automation.
#              Features dynamic repository detection, adaptive network timeout
#              handling, and robust error checking.
#
# Requirements: debmirror, curl, bc, rsync, coreutils, util-linux, findutils,
#               debian-archive-keyring, ubuntu-keyring
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

#═══════════════════════════════════════════════════════════════════════════════
# 1. METADATA AND STYLE CONSTANTS
#═══════════════════════════════════════════════════════════════════════════════

readonly SCRIPT_VERSION="2.9.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly COLOR_RED="\033[0;31m"
readonly COLOR_GREEN="\033[0;32m"
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_CYAN="\033[0;36m"
readonly COLOR_BLUE="\033[0;34m"
readonly COLOR_WHITE="\033[1;37m"
readonly COLOR_RESET="\033[0m"
readonly STYLE_BOLD="\033[1m"

#═══════════════════════════════════════════════════════════════════════════════
# 2. CONFIGURATION & VARIABLES (DEFAULTS)
#═══════════════════════════════════════════════════════════════════════════════

# Basic configuration
declare MIRROR_PATH="${MIRROR_PATH:-/mnt/TOSHIBA/MIRROR}"
declare ARCH="${MIRROR_ARCH:-amd64}"
declare RELEASE_VERSION="stable" # Can be a release alias or a codename
declare DISTRO="debian"          # 'debian' or 'ubuntu'

# Distribution-specific variables (will be set dynamically)
declare MIRROR_HOST=""
declare SECURITY_HOST=""
declare MIRROR_ROOT=""
declare MIRROR_SECURITY_ROOT=""
declare GPG_KEYRING=""
declare SECTIONS=""

# Proxy configuration
declare USE_PROXY="${MIRROR_USE_PROXY:-false}"
declare PROXY="${MIRROR_PROXY:-http://192.168.100.50:8080}"
export WGET_OPTIONS="${WGET_OPTIONS:- --timeout 600 --tries 10 --waitretry 30}"
export CURL_OPTIONS="${CURL_OPTIONS:- --connect-timeout 60 --max-time 1800}"

# Sync method
declare -g SYNC_METHOD="http"

# Operational flags
declare USE_DRY_RUN=false
declare CLEANUP_CORRUPTED="${MIRROR_CLEANUP:-true}"
declare RUN_BANDWIDTH_TEST=true
declare -g CUSTOM_SECTIONS_SET="false" # Flag to track if user provided custom sections

# Space management
declare MIN_SPACE_GB_DESIRED="${MIRROR_MIN_SPACE:-50}"
declare CRITICAL_FREE_SPACE_GB="${MIRROR_CRITICAL_SPACE:-20}"

# Logging and notifications
declare LOG_LEVEL="${MIRROR_LOG_LEVEL:-INFO}"
declare LOG_DIR="${MIRROR_LOG_DIR:-/var/log/mirror-manager}"
declare LOG_MAX_FILES=10
declare NOTIFICATION_EMAIL="${MIRROR_EMAIL:-}"
declare WEBHOOK_URL="${MIRROR_WEBHOOK:-}"
declare CONFIG_FILE="${MIRROR_CONFIG:-}"

# Global state variables
declare -g LOG_FILE=""
declare -g TEMP_DIR=""
declare -g LOCK_FILE=""
declare -g SYNC_FAILED=false
declare -g RESOLVED_CODENAME=""
declare -i LOG_LEVEL_NUM=3
declare -g LOCK_ACQUIRED=false

#═══════════════════════════════════════════════════════════════════════════════
# 3. UTILITY FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

log_message() {
    local level="$1"; local message="$2"; local level_num=0; local color="${COLOR_RESET}"
    case "$level" in
        DEBUG) level_num=4; color="${COLOR_BLUE}";; INFO)  level_num=3; color="${COLOR_GREEN}";;
        WARN)  level_num=2; color="${COLOR_YELLOW}";; ERROR) level_num=1; color="${COLOR_RED}";;
    esac
    if [[ $level_num -le $LOG_LEVEL_NUM ]]; then
        local timestamp; timestamp="$(date "+%Y-%m-%d %H:%M:%S %Z")"
        printf "%b%s [%s] %s%b\n" "$color" "$timestamp" "$level" "$message" "$COLOR_RESET" >&2
        if [[ -n "$LOG_FILE" ]]; then
            printf "%s [%s] %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"
        fi
    fi
}
log_debug() { log_message "DEBUG" "$1"; }
log_info() { log_message "INFO" "$1"; }
log_warning() { log_message "WARN" "$1"; }
log_error() { log_message "ERROR" "$1"; }

send_notification() {
    local subject="$1"; local body="$2"
    if [[ -n "$NOTIFICATION_EMAIL" ]]; then
        log_info "Sending email notification to $NOTIFICATION_EMAIL"
        printf "Subject: %s\n\n%s" "$subject" "$body" | /usr/sbin/sendmail "$NOTIFICATION_EMAIL" || log_warning "Failed to send email."
    fi
    if [[ -n "$WEBHOOK_URL" ]]; then
        log_info "Sending webhook notification."
        local payload; payload=$(printf '{"text": "%s\n%s"}' "$subject" "$body")
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$WEBHOOK_URL" || log_warning "Failed to send webhook."
    fi
}

acquire_lock() {
    log_debug "Attempting to acquire lock: $LOCK_FILE"
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_error "Another instance of $SCRIPT_NAME for ${DISTRO} is already running. Aborting."
        exit 1
    fi
    LOCK_ACQUIRED=true
    log_info "Lock acquired successfully."
}

cleanup_handler() {
    local exit_code=$?
    [[ $LOG_LEVEL_NUM -eq 0 ]] && LOG_LEVEL_NUM=3
    log_info "--- Running cleanup handler (Exit code: $exit_code) ---"
    if $SYNC_FAILED && [[ $exit_code -eq 0 ]]; then
        exit_code=1
    fi
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script finished with errors."
        send_notification "FAILURE: $SCRIPT_NAME sync for $DISTRO failed" "The sync script failed. Check logs at ${LOG_FILE:-not created} for details."
    else
        log_info "Script finished successfully."
    fi
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    [[ "$LOCK_ACQUIRED" == "true" ]] && rm -f "$LOCK_FILE"
    log_info "--- Cleanup finished ---"
}


#═══════════════════════════════════════════════════════════════════════════════
# 4. CONFIGURATION AND INITIALIZATION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

show_help() {
    printf "\n${STYLE_BOLD}${COLOR_CYAN}Universal Mirror Manager v${SCRIPT_VERSION}${COLOR_RESET}\n"
    printf "A robust script for creating local Debian and Ubuntu mirrors.\n\n"
    printf "${STYLE_BOLD}USAGE:${COLOR_RESET}\n"
    printf "    %s [OPTIONS] [release-version]\n\n" "$SCRIPT_NAME"
    printf "    This script synchronizes a specific distribution release. You can specify the\n"
    printf "    distribution with '--distro' and the version as the final argument.\n\n"
    printf "    ${STYLE_BOLD}release-version:${COLOR_RESET} (Optional) Codename or alias (e.g., bookworm, noble, stable, lts, testing).\n"
    printf "                     Default: \"%s\"\n\n" "$RELEASE_VERSION"
    printf "${STYLE_BOLD}OPTIONS:${COLOR_RESET}\n"
    printf "    %-35s %s\n" "--distro [debian|ubuntu]" "Distribution to mirror (Default: $DISTRO)"
    printf "    %-35s %s\n" "-p, --path PATH" "Mirror base directory (Default: $MIRROR_PATH)"
    printf "    %-35s %s\n" "-a, --arch ARCH" "Architecture to download (Default: $ARCH)"
    printf "    %-35s %s\n" "-s, --sections SECTIONS" "Comma-separated list of sections (Overrides distro default)"
    printf "    %-35s %s\n" "--use-rsync" "Use rsync for synchronization instead of http"
    printf "    %-35s %s\n" "-d, --dry-run" "Simulate without downloading"
    printf "    %-35s %s\n" "-c, --config FILE" "Path to a custom configuration file"
    printf "    %-35s %s\n" "--cleanup" "Scan for and remove corrupted files (Default: on)"
    printf "    %-35s %s\n" "--no-bandwidth-test" "Disable the initial bandwidth test"
    printf "    %-35s %s\n" "--log-level LEVEL" "Set log verbosity: DEBUG, INFO, WARN, ERROR"
    printf "    %-35s %s\n" "--email EMAIL" "Email address for notifications"
    printf "    %-35s %s\n" "--webhook URL" "Webhook URL for notifications"
    printf "    %-35s %s\n" "-v, --version" "Show script version"
    printf "    %-35s %s\n" "-h, --help" "Show this help message\n"
    printf "${STYLE_BOLD}EXAMPLES:${COLOR_RESET}\n"
    printf "    # Sync Debian stable (default behavior)\n"
    printf "    %s\n\n" "$SCRIPT_NAME"
    printf "    # Dry-run sync for Ubuntu 24.04 LTS (noble)\n"
    printf "    %s --dry-run --distro ubuntu noble\n\n" "$SCRIPT_NAME"
    printf "    # Sync Debian testing, but only the 'main' section\n"
    printf "    %s --sections main testing\n\n" "$SCRIPT_NAME"
}

process_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --distro) DISTRO="$2"; shift 2 ;;
            -p|--path) MIRROR_PATH="$2"; shift 2 ;;
            -a|--arch) ARCH="$2"; shift 2 ;;
            -s|--sections) SECTIONS="$2"; CUSTOM_SECTIONS_SET="true"; shift 2 ;;
            --use-rsync) SYNC_METHOD="rsync"; shift ;;
            -d|--dry-run) USE_DRY_RUN=true; shift ;;
            -c|--config) CONFIG_FILE="$2"; shift 2 ;;
            --cleanup) CLEANUP_CORRUPTED=true; shift ;;
            --no-bandwidth-test) RUN_BANDWIDTH_TEST=false; shift ;;
            --log-level) LOG_LEVEL="$2"; shift 2 ;;
            --email) NOTIFICATION_EMAIL="$2"; shift 2 ;;
            --webhook) WEBHOOK_URL="$2"; shift 2 ;;
            -v|--version) shift ;; 
            -h|--help) shift ;;
            -*) log_error "Unknown option: $1"; exit 1 ;;
            *) break ;;
        esac
    done
    if [[ $# -gt 0 ]]; then RELEASE_VERSION="$1"; shift; fi
    if [[ $# -gt 0 ]]; then log_error "Unexpected arguments: '$*'"; exit 1; fi
}

load_configuration_file() {
    if [[ -n "$CONFIG_FILE" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            log_info "Loading configuration from $CONFIG_FILE"
            source "$CONFIG_FILE"
        else
            log_error "Configuration file not found: $CONFIG_FILE"; exit 1
        fi
    fi
}

initialize_system() {
    case "${LOG_LEVEL^^}" in
        DEBUG) LOG_LEVEL_NUM=4;; INFO) LOG_LEVEL_NUM=3;; WARN) LOG_LEVEL_NUM=2;; ERROR) LOG_LEVEL_NUM=1;;
        *) local old_level=$LOG_LEVEL; LOG_LEVEL="INFO"; LOG_LEVEL_NUM=3; log_warning "Invalid LOG_LEVEL '$old_level'. Defaulting to INFO." ;;
    esac

    mkdir -p "$LOG_DIR" || { log_error "Failed to create log directory: $LOG_DIR"; exit 1; }
    LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-${DISTRO}-$(date "+%Y%m%d_%H%M%S").log"
    find "$LOG_DIR" -type f -name "${SCRIPT_NAME}-*.log" | sort -r | tail -n +$((LOG_MAX_FILES + 1)) | xargs --no-run-if-empty rm
    TEMP_DIR=$(mktemp -d -t mirror_manager_XXXXXXXX)
    LOCK_FILE="/tmp/${SCRIPT_NAME}_${DISTRO}.lock"
}

set_distro_config() {
    log_info "Configuring for distribution: ${DISTRO}"
    local default_sections=""
    case "$DISTRO" in
        debian)
            MIRROR_HOST="${DEBIAN_MIRROR_HOST:-deb.debian.org}"
            SECURITY_HOST="${DEBIAN_SECURITY_HOST:-security.debian.org}"
            MIRROR_ROOT="${DEBIAN_MIRROR_ROOT:-debian}"
            MIRROR_SECURITY_ROOT="${DEBIAN_MIRROR_SECURITY_ROOT:-debian-security}"
            GPG_KEYRING="/usr/share/keyrings/debian-archive-keyring.gpg"
            default_sections="main,contrib,non-free,non-free-firmware"
            ;;
        ubuntu)
            MIRROR_HOST="${UBUNTU_MIRROR_HOST:-archive.ubuntu.com}"
            SECURITY_HOST="${UBUNTU_SECURITY_HOST:-security.ubuntu.com}"
            MIRROR_ROOT="${UBUNTU_MIRROR_ROOT:-ubuntu}"
            MIRROR_SECURITY_ROOT="${UBUNTU_SECURITY_ROOT:-ubuntu}"
            GPG_KEYRING="/usr/share/keyrings/ubuntu-archive-keyring.gpg"
            default_sections="main,restricted,universe,multiverse"
            ;;
        *)
            log_error "Unsupported distribution: '$DISTRO'. Use 'debian' or 'ubuntu'."
            exit 1
            ;;
    esac

    if [[ "$CUSTOM_SECTIONS_SET" == "true" ]]; then
        log_warning "User has overridden default sections for $DISTRO."
        log_warning "Default would be: '$default_sections'"
        log_warning "Using custom: '$SECTIONS'. Ensure these are valid for the mirror."
    else
        SECTIONS="$default_sections"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 5. VALIDATION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

validate_dependencies() {
    log_info "Validating dependencies..."
    local -A dep_map=([debmirror]=debmirror [curl]=curl [bc]=bc [rsync]=rsync [flock]=util-linux)
    local missing_cmds=()
    for cmd in "${!dep_map[@]}"; do command -v "$cmd" &>/dev/null || missing_cmds+=("$cmd"); done
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_error "Missing required command(s): ${missing_cmds[*]}. Please install them."
        return 1
    fi
    log_info "All dependencies are satisfied."
}

resolve_release_version() {
    local version_to_resolve="$RELEASE_VERSION"
    log_info "Resolving release version for '${version_to_resolve}'..."

    local curl_cmd=(curl ${CURL_OPTIONS} -sL)
    $USE_PROXY && curl_cmd+=(--proxy "$PROXY")
    
    # Check if it's an alias that needs resolving.
    if [[ "$version_to_resolve" =~ ^(stable|lts|testing|unstable)$ ]]; then
        # Handle Ubuntu's 'stable' -> 'lts' mapping
        if [[ "$DISTRO" == "ubuntu" && "$version_to_resolve" == "stable" ]]; then
            version_to_resolve="lts"
            log_info "For Ubuntu, 'stable' alias is mapped to 'lts' for resolution."
        fi

        # Use the canonical metadata file for Ubuntu LTS, as it's the most robust method.
        if [[ "$DISTRO" == "ubuntu" && "$version_to_resolve" == "lts" ]]; then
            log_debug "Using Ubuntu's canonical metadata to resolve LTS codename."
            local meta_url="https://changelogs.ubuntu.com/meta-release-lts"

	    RESOLVED_CODENAME=$("${curl_cmd[@]}" "$meta_url" | awk -F': ' '/^Dist:/ {print $2}' | tail -n 1)
        else
            # For all other aliases (Debian stable/testing, etc.), use the Release file method.
            log_debug "Using Release file method to resolve alias '${version_to_resolve}'."
            local release_file_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${version_to_resolve}/Release"
            RESOLVED_CODENAME=$("${curl_cmd[@]}" "$release_file_url" | grep -oP '^Codename: \K\S+')
        fi

        if [[ -z "$RESOLVED_CODENAME" ]]; then
            log_error "Could not resolve codename for alias '${version_to_resolve}'."
            return 1
        fi
        log_info "Successfully resolved '${RELEASE_VERSION}' to codename '${RESOLVED_CODENAME}'"
    else
        # If not an alias, validate the provided codename directly.
        log_debug "Validating provided codename '${version_to_resolve}'."
        local release_file_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${version_to_resolve}/Release"
        if "${curl_cmd[@]}" --fail "$release_file_url" &> /dev/null; then
            RESOLVED_CODENAME="$version_to_resolve"
            log_info "Codename '${RESOLVED_CODENAME}' is valid and exists on the mirror."
        else
            log_error "Invalid or non-existent codename: '${version_to_resolve}' on ${MIRROR_HOST}."
            return 1
        fi
    fi
}

validate_environment() {
    log_info "Validating environment..."
    mkdir -p "${MIRROR_PATH}/${MIRROR_ROOT}" "${MIRROR_PATH}/${MIRROR_SECURITY_ROOT}"
    for path in "${MIRROR_PATH}/${MIRROR_ROOT}" "${MIRROR_PATH}/${MIRROR_SECURITY_ROOT}"; do
        if ! [[ -w "$path" ]]; then log_error "Mirror path '$path' is not writable."; return 1; fi
    done
    local free_space_kb; free_space_kb=$(df -kP "$MIRROR_PATH" | awk 'NR==2 {print $4}')
    local free_space_gb; free_space_gb=$(bc <<< "scale=2; ${free_space_kb} / 1024 / 1024")
    log_info "Available space for '$MIRROR_PATH': ${free_space_gb} GB"
    if (( $(echo "$free_space_gb < $CRITICAL_FREE_SPACE_GB" | bc -l) )); then
        log_error "CRITICAL LOW SPACE: ${free_space_gb}GB available < ${CRITICAL_FREE_SPACE_GB}GB required."
        return 1
    elif (( $(echo "$free_space_gb < $MIN_SPACE_GB_DESIRED" | bc -l) )); then
        log_warning "LOW SPACE WARNING: Only ${free_space_gb}GB available. Desired min is ${MIN_SPACE_GB_DESIRED}GB."
    fi
    
    if ! [[ -f "$GPG_KEYRING" ]]; then
        local pkg_name="${DISTRO}-archive-keyring"
        log_error "GPG keyring not found at '$GPG_KEYRING'."
        printf "\n    ${COLOR_CYAN}To fix this, please run: sudo apt install %s${COLOR_RESET}\n\n" "$pkg_name"
        return 1
    fi
    log_info "Environment validation successful."
}

#═══════════════════════════════════════════════════════════════════════════════
# 6. SYNC PREPARATION & EXECUTION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

perform_bandwidth_test() {
    if ! $RUN_BANDWIDTH_TEST; then log_info "Skipping bandwidth test."; return; fi
    log_info "Estimating network bandwidth (this may take a moment)..."
    local test_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/ls-lR.gz"
    local temp_file="$TEMP_DIR/bw_test"
    local curl_output
    curl_output=$(timeout 30s curl ${CURL_OPTIONS} -o "$temp_file" -w "%{size_download}:%{time_total}" -s "$test_url" 2>/dev/null || echo "0:0")
    local size_bytes="${curl_output%%:*}"; local time_s="${curl_output##*:}"
    rm -f "$temp_file"
    if [[ "$size_bytes" -gt 0 && "$(echo "$time_s > 0.1" | bc -l)" -eq 1 ]]; then
        local speed_mbps; speed_mbps=$(bc <<< "scale=2; ($size_bytes * 8) / $time_s / 1000000")
        log_info "Estimated download speed: ${speed_mbps} Mbps"
        if (( $(echo "$speed_mbps < 5" | bc -l) )); then
            export WGET_OPTIONS="--timeout=1200 --tries=20 --waitretry=60"
            export CURL_OPTIONS="--connect-timeout 120 --max-time 3600"
            log_warning "Slow connection detected. Adjusting network timeouts to be more tolerant."
        fi
    else
        log_warning "Could not reliably measure bandwidth. Proceeding with default timeouts."
    fi
}

cleanup_corrupted_files() {
    if ! $CLEANUP_CORRUPTED; then return; fi
    log_warning "Scanning for corrupted/partial files in $MIRROR_PATH..."
    local found_files; found_files=$(find "$MIRROR_PATH" -type f \( -name "*.PART" -o -name "*.FAILED" \) -print -delete)
    if [[ -n "$found_files" ]]; then
        log_warning "Removed the following files:"
        echo "$found_files" | while IFS= read -r line; do log_warning "  - $line"; done
    else
        log_info "No corrupted/partial files found."
    fi
}

run_debmirror() {
    local repo_type="$1"; local host="$2"; local root="$3"; local dists="$4"; local target_path="$5"
    if [[ -z "$dists" ]]; then
        log_info "No distributions to sync for ${repo_type}. Skipping."
        return
    fi
    log_info "--- Starting sync for ${repo_type} (${dists}) into '${target_path}' ---"
    local debmirror_cmd=(
        debmirror --progress --ignore-release-gpg --keyring="$GPG_KEYRING" --host="$host"
        --root="$root" --dist="$dists" --section="$SECTIONS" --arch="$ARCH" --method="$SYNC_METHOD"
        --rsync-extra=none --diff=none
    )
    $USE_PROXY && [[ "$SYNC_METHOD" == "http" ]] && debmirror_cmd+=(--proxy="$PROXY")
    $USE_DRY_RUN && debmirror_cmd+=(--dry-run)
    local output_file="${TEMP_DIR}/debmirror_${repo_type}.log"
    log_debug "Executing Debmirror command: ${debmirror_cmd[*]} ${target_path}"
    
    "${debmirror_cmd[@]}" "$target_path" 2>&1 | tee "$output_file"
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -ne 0 ]] || grep -q -i -E '^(error|fatal):|i/o error|failed to|Download of .* failed' "$output_file"; then
        log_error "Debmirror task '${repo_type}' finished with issues. Exit code: $exit_code."
        SYNC_FAILED=true
    else
        log_info "Successfully completed sync for ${repo_type}."
    fi
    log_info "--- Finished sync for ${repo_type} ---"
}

#═══════════════════════════════════════════════════════════════════════════════
# 8. MAIN EXECUTION
#═══════════════════════════════════════════════════════════════════════════════

main() {
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then show_help; exit 0; fi
        if [[ "$arg" == "-v" || "$arg" == "--version" ]]; then echo "$SCRIPT_NAME v$SCRIPT_VERSION"; exit 0; fi
    done

    trap cleanup_handler EXIT
    load_configuration_file
    process_arguments "$@"
    initialize_system
    set_distro_config
    
    log_info "Starting $SCRIPT_NAME v$SCRIPT_VERSION for $DISTRO (PID: $$)"
    acquire_lock

    {
        validate_dependencies &&
        resolve_release_version &&
        validate_environment
    } || exit 1

    declare -a main_releases_arr=("$RESOLVED_CODENAME")
    declare security_releases=""
    log_info "Dynamically checking for available repositories for '${RESOLVED_CODENAME}'..."
    local curl_cmd=(curl -sL --fail ${CURL_OPTIONS})
    $USE_PROXY && curl_cmd+=(--proxy "$PROXY")

    for repo_suffix in "updates" "proposed" "backports"; do
        local repo_to_check="${RESOLVED_CODENAME}-${repo_suffix}"
        if [[ "$DISTRO" == "debian" && "$repo_suffix" == "proposed" ]]; then
            repo_to_check="${RESOLVED_CODENAME}-proposed-updates"
        elif [[ "$DISTRO" == "ubuntu" && "$repo_suffix" == "proposed-updates" ]]; then
            continue 
        fi
        
        local release_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${repo_to_check}/Release"
        log_debug "Checking for main repository component: $release_url"
        if "${curl_cmd[@]}" "$release_url" &> /dev/null; then
            log_info "Found '${repo_to_check}'. Adding to sync list."
            main_releases_arr+=("$repo_to_check")
        else
            log_debug "Component '${repo_to_check}' not found. Skipping."
        fi
    done

    local security_repo_name="${RESOLVED_CODENAME}-security"
    local security_url="http://${SECURITY_HOST}/${MIRROR_SECURITY_ROOT}/dists/${security_repo_name}/Release"
    log_debug "Checking for security repository: $security_url"
    if "${curl_cmd[@]}" "$security_url" &> /dev/null; then
        log_info "Found security repository '${security_repo_name}'. Adding to sync list."
        security_releases="$security_repo_name"
    else
        log_info "Security repository for '${RESOLVED_CODENAME}' not found. Skipping."
    fi

    local main_releases
    main_releases=$(IFS=,; echo "${main_releases_arr[*]}")
    log_info "Final main distributions list: ${main_releases}"
    log_info "Final security distributions list: ${security_releases:-None}"

    perform_bandwidth_test
    cleanup_corrupted_files

    local original_sync_method=$SYNC_METHOD
    run_debmirror "main_repo" "$MIRROR_HOST" "$MIRROR_ROOT" "$main_releases" "${MIRROR_PATH}/${MIRROR_ROOT}"

    if ! $SYNC_FAILED; then
        if [[ "$original_sync_method" == "rsync" ]]; then
            log_info "Forcing http method for security repository (rsync is often unavailable)."
            SYNC_METHOD="http"
        fi
        run_debmirror "security_repo" "$SECURITY_HOST" "$MIRROR_SECURITY_ROOT" "$security_releases" "${MIRROR_PATH}/${MIRROR_SECURITY_ROOT}"
    else
        log_warning "Skipping security sync due to failure in main repository sync."
    fi
    SYNC_METHOD=$original_sync_method

    if $SYNC_FAILED; then
        exit 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
