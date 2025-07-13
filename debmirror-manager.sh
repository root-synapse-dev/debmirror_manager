#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# DEBIAN MIRROR MANAGER
#═══════════════════════════════════════════════════════════════════════════════
# Script:      debmirror-manager
# Version:     1.1.1-RC1
# Author:      Synapse Dev Ω (Powered with AI)
# License:     MIT
# Description: Enterprise-grade Debian repository mirror automation. Uses a
#              separate directory for each repository and features adaptive
#              network timeout handling for slow connections.
#
# Requirements: debmirror, curl, bc, rsync, coreutils, util-linux, findutils
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

#═══════════════════════════════════════════════════════════════════════════════
# 1. METADATA AND STYLE CONSTANTS
#═══════════════════════════════════════════════════════════════════════════════

readonly SCRIPT_VERSION="1.1.1-RC1"
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
declare MIRROR_PATH="${DEBMIRROR_PATH:-/mnt/TOSHIBA/MIRROR}"
declare ARCH="${DEBMIRROR_ARCH:-amd64}"
declare SECTIONS="${DEBMIRROR_SECTIONS:-main,contrib,non-free,non-free-firmware}"
declare DEBIAN_VERSION="stable"

# Mirror hosts
declare MIRROR_HOST="${DEBMIRROR_HOST:-deb.debian.org}"
declare SECURITY_HOST="${DEBMIRROR_SECURITY_HOST:-security.debian.org}"
declare MIRROR_ROOT="${DEBMIRROR_ROOT:-debian}"
declare MIRROR_SECURITY_ROOT="${DEBMIRROR_SECURITY_ROOT:-debian-security}"

# Proxy configuration
declare USE_PROXY="${DEBMIRROR_USE_PROXY:-false}"
declare PROXY="${DEBMIRROR_PROXY:-http://192.168.100.50:8080}"
export WGET_OPTIONS="${WGET_OPTIONS:- --timeout 600 --tries 10 --waitretry 30}"
export CURL_OPTIONS="${CURL_OPTIONS:- --connect-timeout 60 --max-time 1800}"

# Sync method
declare -g SYNC_METHOD="http"

# Operational flags
declare USE_DRY_RUN=false
declare CLEANUP_CORRUPTED="${DEBMIRROR_CLEANUP:-true}"
declare RUN_BANDWIDTH_TEST=true

# Space management
declare MIN_SPACE_GB_DESIRED="${DEBMIRROR_MIN_SPACE:-50}"
declare CRITICAL_FREE_SPACE_GB="${DEBMIRROR_CRITICAL_SPACE:-20}"
declare MAX_SYNC_DURATION="${DEBMIRROR_MAX_DURATION:-28800}" # 8 horas

# Logging and notifications
declare LOG_LEVEL="${DEBMIRROR_LOG_LEVEL:-INFO}"
declare LOG_DIR="${DEBMIRROR_LOG_DIR:-/var/log/debmirror}"
declare LOG_MAX_FILES=10
declare NOTIFICATION_EMAIL="${DEBMIRROR_EMAIL:-}"
declare WEBHOOK_URL="${DEBMIRROR_WEBHOOK:-}"
declare CONFIG_FILE="${DEBMIRROR_CONFIG:-}"

# System paths and files
readonly GPG_KEYRING="/usr/share/keyrings/debian-archive-keyring.gpg"

# Global variables
declare -g LOG_FILE=""
declare -g TEMP_DIR=""
declare -g LOCK_FILE=""
declare -g SYNC_FAILED=false
declare -g RESOLVED_DEBIAN_VERSION=""
declare -i LOG_LEVEL_NUM=3
declare -g LOCK_ACQUIRED=false

#═══════════════════════════════════════════════════════════════════════════════
# 3. UTILITY FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Logging functions
log_message() {
    local level="$1"
    local message="$2"
    local level_num=0
    local color="${COLOR_RESET}"

    case "$level" in
        DEBUG) level_num=4; color="${COLOR_BLUE}";;
        INFO)  level_num=3; color="${COLOR_GREEN}";;
        WARN)  level_num=2; color="${COLOR_YELLOW}";;
        ERROR) level_num=1; color="${COLOR_RED}";;
    esac

    if [[ $level_num -le $LOG_LEVEL_NUM ]]; then
        local timestamp
        timestamp="$(date "+%Y-%m-%d %H:%M:%S %Z")"
        printf "%b%s [%s] %s%b\n" "$color" "$timestamp" "$level" "$message" "$COLOR_RESET" >&2

        if [[ -n "$LOG_FILE" ]]; then
            printf "%s [%s] %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"
        fi
    fi
}

log_debug() {
    log_message "DEBUG" "$1"
}

log_info() {
    log_message "INFO" "$1"
}

log_warning() {
    log_message "WARN" "$1"
}

log_error() {
    log_message "ERROR" "$1"
}

# Notification functions
send_notification() {
    local subject="$1"
    local body="$2"

    if [[ -n "$NOTIFICATION_EMAIL" ]]; then
        log_info "Sending email notification to $NOTIFICATION_EMAIL"
        printf "Subject: %s\n\n%s" "$subject" "$body" | /usr/sbin/sendmail "$NOTIFICATION_EMAIL" || log_warning "Failed to send email."
    fi

    if [[ -n "$WEBHOOK_URL" ]]; then
        log_info "Sending webhook notification."
        local payload
        payload=$(printf '{"text": "%s\n%s"}' "$subject" "$body")
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$WEBHOOK_URL" || log_warning "Failed to send webhook."
    fi
}

# Lock management
acquire_lock() {
    log_debug "Attempting to acquire lock: $LOCK_FILE"
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_error "Another instance of $SCRIPT_NAME is already running. Aborting."
        exit 1
    fi
    LOCK_ACQUIRED=true
    log_info "Lock acquired successfully."
}

# Cleanup handler
cleanup_handler() {
    local exit_code=$?
    log_info "--- Running cleanup handler ---"

    if $SYNC_FAILED && [[ $exit_code -eq 0 ]]; then
        exit_code=1
    fi

    if [[ $exit_code -ne 0 ]]; then
        log_error "Script finished with errors (exit code: $exit_code)."
        send_notification "FAILURE: $SCRIPT_NAME sync failed" "The sync script failed. Check logs at $LOG_FILE for details."
    else
        log_info "Script finished successfully."
    fi

    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi

    # Solo eliminar el archivo de bloqueo si este proceso lo adquirió
    if [[ "$LOCK_ACQUIRED" == "true" ]]; then
        rm -f "$LOCK_FILE"
    fi

    log_info "--- Cleanup finished ---"
}

#═══════════════════════════════════════════════════════════════════════════════
# 4. CONFIGURATION AND INITIALIZATION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Help display
show_help() {
    printf "\n${STYLE_BOLD}${COLOR_CYAN}Debmirror Manager v${SCRIPT_VERSION}${COLOR_RESET}\n"
    printf "A robust, enterprise-grade script for creating local Debian mirrors.\n\n"

    printf "${STYLE_BOLD}USAGE:${COLOR_RESET}\n"
    printf "    %s [OPTIONS] [debian-version]\n\n" "$SCRIPT_NAME"
    printf "    debian-version: (Optional) The codename of the Debian release (e.g., bookworm, stable).\n"
    printf "                    Default: \"%s\"\n\n" "$DEBIAN_VERSION"

    printf "${STYLE_BOLD}OPTIONS:${COLOR_RESET}\n"
    printf "    %-35s %s\n" "-p, --path PATH" "Mirror base directory (Default: $MIRROR_PATH)"
    printf "    %-35s %s\n" "-a, --arch ARCH" "Architecture to download (Default: $ARCH)"
    printf "    %-35s %s\n" "-s, --sections SECTIONS" "Comma-separated list of sections (Default: \"$SECTIONS\")"
    printf "    %-35s %s\n" "--use-rsync" "Use rsync for synchronization instead of the default http."
    printf "    %-35s %s\n" "-d, --dry-run" "Simulate without downloading"
    printf "    %-35s %s\n" "-c, --config FILE" "Path to a custom configuration file"
    printf "    %-35s %s\n" "--cleanup" "Scan for and remove corrupted files before syncing"
    printf "    %-35s %s\n" "--no-bandwidth-test" "Disable the initial bandwidth test."
    printf "    %-35s %s\n" "--log-level LEVEL" "Set log verbosity: DEBUG, INFO, WARN, ERROR (Default: $LOG_LEVEL)"
    printf "    %-35s %s\n" "--email EMAIL" "Email address for notifications"
    printf "    %-35s %s\n" "--webhook URL" "Webhook URL for notifications"
    printf "    %-35s %s\n" "-v, --version" "Show script version"
    printf "    %-35s %s\n" "-h, --help" "Show this help message"

    printf "\n${STYLE_BOLD}ENVIRONMENT VARIABLES:${COLOR_RESET}\n"
    printf "    The script can also be configured via environment variables, which are overridden by flags.\n"
    printf "    %-35s %s\n" "DEBMIRROR_PATH" "Overrides --path. Default: $MIRROR_PATH"
    printf "    %-35s %s\n" "DEBMIRROR_HOST" "Main mirror host. Default: $MIRROR_HOST"
    printf "    %-35s %s\n" "DEBMIRROR_SECURITY_HOST" "Security mirror host. Default: $SECURITY_HOST"
    printf "    %-35s %s\n" "DEBMIRROR_USE_PROXY" "Set to 'true' to use a proxy. Default: $USE_PROXY"
    printf "    %-35s %s\n" "DEBMIRROR_PROXY" "Proxy URL (e.g., http://user:pass@host:port)"
    printf "    %-35s %s\n" "DEBMIRROR_MIN_SPACE" "Warn if free space (GB) is below this. Default: $MIN_SPACE_GB_DESIRED"
    printf "    %-35s %s\n" "DEBMIRROR_CRITICAL_SPACE" "Abort if free space (GB) is below this. Default: $CRITICAL_FREE_SPACE_GB"
    printf "\n"
}

# Argument processing
process_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--path)
                MIRROR_PATH="$2"
                shift 2
                ;;
            -a|--arch)
                ARCH="$2"
                shift 2
                ;;
            -s|--sections)
                SECTIONS="$2"
                shift 2
                ;;
            --use-rsync)
                SYNC_METHOD="rsync"
                shift
                ;;
            -d|--dry-run)
                USE_DRY_RUN=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --cleanup)
                CLEANUP_CORRUPTED=true
                shift
                ;;
            --no-bandwidth-test)
                RUN_BANDWIDTH_TEST=false
                shift
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --email)
                NOTIFICATION_EMAIL="$2"
                shift 2
                ;;
            --webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done

    if [[ $# -gt 0 ]]; then
        DEBIAN_VERSION="$1"
        shift
    fi

    if [[ $# -gt 0 ]]; then
        log_error "Unexpected arguments: '$*'"
        exit 1
    fi
}

# Configuration file loading
load_configuration_file() {
    if [[ -n "$CONFIG_FILE" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            log_info "Loading configuration from $CONFIG_FILE"
            source "$CONFIG_FILE"
        else
            log_error "Configuration file not found: $CONFIG_FILE"
            exit 1
        fi
    fi
}

# System initialization
initialize_system() {
    case "${LOG_LEVEL^^}" in
        DEBUG) LOG_LEVEL_NUM=4;;
        INFO)  LOG_LEVEL_NUM=3;;
        WARN)  LOG_LEVEL_NUM=2;;
        ERROR) LOG_LEVEL_NUM=1;;
        *)
            log_warning "Invalid LOG_LEVEL '$LOG_LEVEL'. Defaulting to INFO."
            LOG_LEVEL_NUM=3
            ;;
    esac

    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date "+%Y%m%d_%H%M%S").log"

    # Cleanup old log files
    find "$LOG_DIR" -type f -name "${SCRIPT_NAME}-*.log" | sort -r | tail -n +$((LOG_MAX_FILES + 1)) | xargs --no-run-if-empty rm

    TEMP_DIR=$(mktemp -d -t debmirror_XXXXXXXX)
    LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
}

#═══════════════════════════════════════════════════════════════════════════════
# 5. VALIDATION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Dependency validation
validate_dependencies() {
    log_info "Validating dependencies..."

    declare -A dep_map=(
        [debmirror]="debmirror"
        [curl]="curl"
        [bc]="bc"
        [rsync]="rsync"
        [flock]="util-linux"
    )

    local missing_cmds=()
    local packages_to_install=()
    local checked_packages=()

    for cmd in "${!dep_map[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_cmds+=("$cmd")
            local pkg="${dep_map[$cmd]}"
            if ! [[ " ${checked_packages[*]} " =~ " ${pkg} " ]]; then
                packages_to_install+=("$pkg")
                checked_packages+=("$pkg")
            fi
        fi
    done

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_error "Missing required command(s): ${missing_cmds[*]}"

        if [[ ${#packages_to_install[@]} -gt 0 ]] && command -v apt &> /dev/null; then
            local install_cmd="apt install ${packages_to_install[*]}"
            log_info "On a Debian-based system, you can install the required packages by running:"
            printf "\n    ${COLOR_CYAN}sudo apt update && sudo %s${COLOR_RESET}\n\n" "$install_cmd"
        else
            log_warning "Could not detect 'apt'. Please install the missing dependencies using your system's package manager."
        fi

        return 1
    fi

    log_info "All dependencies are satisfied."
}

# Debian version resolution
resolve_debian_version() {
    log_info "Resolving Debian version for '${DEBIAN_VERSION}'..."

    # Preparamos el comando curl que usaremos en ambos casos
    local curl_cmd=(curl ${CURL_OPTIONS} -sL)
    if $USE_PROXY; then
        curl_cmd+=(--proxy "$PROXY")
    fi

    if [[ "$DEBIAN_VERSION" == "stable" || "$DEBIAN_VERSION" == "testing" || "$DEBIAN_VERSION" == "unstable" ]]; then
        # CASO 1: Es un alias como 'stable'. Hay que resolverlo.
        local release_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${DEBIAN_VERSION}/Release"

        RESOLVED_DEBIAN_VERSION=$("${curl_cmd[@]}" "$release_url" | grep -oP '^Codename: \K\S+')

        if [[ -z "$RESOLVED_DEBIAN_VERSION" ]]; then
            log_error "Could not resolve codename for '${DEBIAN_VERSION}'. Check network or mirror host."
            return 1
        fi

        log_info "Resolved '${DEBIAN_VERSION}' to codename '${RESOLVED_DEBIAN_VERSION}'"
    else
        # CASO 2: Se proporcionó un nombre de código (ej: bookworm, trixie). HAY QUE VALIDARLO.
        log_info "Validating provided codename '${DEBIAN_VERSION}'..."
        local release_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${DEBIAN_VERSION}/Release"

        # Usamos curl con --fail, que devuelve un error si el HTTP status es 4xx o 5xx (como 404 Not Found)
        if "${curl_cmd[@]}" --fail "$release_url" &> /dev/null; then
            # Si el comando tiene éxito (exit code 0), el archivo existe y el codename es válido.
            RESOLVED_DEBIAN_VERSION="$DEBIAN_VERSION"
            log_info "Codename '${RESOLVED_DEBIAN_VERSION}' is valid and exists on the mirror."
        else
            # Si el comando falla, el codename es incorrecto.
            log_error "Invalid or non-existent Debian codename: '${DEBIAN_VERSION}'."
            log_error "Please provide a valid codename (e.g., bookworm, trixie) or a release channel (stable, testing)."
            return 1 # Devolvemos un error para detener el script
        fi
    fi
}

# Environment validation
validate_environment() {
    log_info "Validating environment..."

    local main_repo_path="${MIRROR_PATH}/${MIRROR_ROOT}"
    local security_repo_path="${MIRROR_PATH}/${MIRROR_SECURITY_ROOT}"

    # Main repository directory
    log_info "Ensuring main repository directory exists: $main_repo_path"
    mkdir -p "$main_repo_path" || {
        log_error "Main mirror path '$main_repo_path' could not be created."
        return 1
    }

    [[ -w "$main_repo_path" ]] || {
        log_error "Main mirror path '$main_repo_path' is not writable."
        return 1
    }

    # Security repository directory
    log_info "Ensuring security repository directory exists: $security_repo_path"
    mkdir -p "$security_repo_path" || {
        log_error "Security mirror path '$security_repo_path' could not be created."
        return 1
    }

    [[ -w "$security_repo_path" ]] || {
        log_error "Security mirror path '$security_repo_path' is not writable."
        return 1
    }

    # Disk space validation
    local free_space_kb
    free_space_kb=$(df -kP "$MIRROR_PATH" | awk 'NR==2 {print $4}')
    local free_space_gb
    free_space_gb=$(bc <<< "scale=2; ${free_space_kb} / 1024 / 1024")

    log_info "Available space on device for base path '$MIRROR_PATH': ${free_space_gb} GB"

    if (( $(echo "$free_space_gb < $CRITICAL_FREE_SPACE_GB" | bc -l) )); then
        log_error "CRITICAL LOW SPACE: Only ${free_space_gb}GB available, require at least ${CRITICAL_FREE_SPACE_GB}GB. Aborting."
        return 1
    elif (( $(echo "$free_space_gb < $MIN_SPACE_GB_DESIRED" | bc -l) )); then
        log_warning "LOW SPACE WARNING: Only ${free_space_gb}GB available. Desired minimum is ${MIN_SPACE_GB_DESIRED}GB. Sync will continue."
        send_notification "WARNING: Low disk space on mirror" "Mirror path ${MIRROR_PATH} has ${free_space_gb}GB free. The sync will continue, but please check the disk soon."
    fi

    # GPG keyring validation
    [[ -f "$GPG_KEYRING" ]] || {
        log_error "GPG keyring not found at '$GPG_KEYRING'. Please install 'debian-archive-keyring'."
        return 1
    }

    log_info "Environment validation successful."
}

#═══════════════════════════════════════════════════════════════════════════════
# 6. SYNC PREPARATION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Bandwidth testing
perform_bandwidth_test() {
    if ! $RUN_BANDWIDTH_TEST; then
        log_info "Skipping bandwidth test."
        return
    fi

    log_info "Estimating network bandwidth (this may take a moment)..."

    local test_url="http://${MIRROR_HOST}/${MIRROR_ROOT}/ls-lR.gz"
    local temp_file="$TEMP_DIR/bandwidth_test_file"
    local curl_output

    curl_output=$(timeout 30s curl ${CURL_OPTIONS} -o "$temp_file" -w "%{size_download}:%{time_total}" -s "$test_url" 2>/dev/null || echo "0:0")

    local size_bytes="${curl_output%%:*}"
    local time_s="${curl_output##*:}"

    rm -f "$temp_file"

    if [[ "$size_bytes" -gt 0 && "$(echo "$time_s > 0.1" | bc -l)" -eq 1 ]]; then
        local speed_bps
        speed_bps=$(echo "scale=0; ($size_bytes * 8) / $time_s" | bc)
        local speed_mbps
        speed_mbps=$(echo "scale=2; $speed_bps / 1000000" | bc)

        log_info "Estimated download speed: ${speed_mbps} Mbps"

        if (( $(echo "$speed_mbps < 5" | bc -l) )); then
            export WGET_OPTIONS="--timeout=1200 --tries=20 --waitretry=60"
            export CURL_OPTIONS="--connect-timeout 120 --max-time 3600"
            log_warning "Slow connection detected. Adjusting network timeouts to be more tolerant."
        fi
    else
        log_warning "Could not reliably measure bandwidth. Proceeding with default timeouts."
        if [[ "$curl_output" == "0:0" ]]; then
            log_warning "Bandwidth test download failed. Check network or proxy settings."
        fi
    fi
}

# Corrupted files cleanup
cleanup_corrupted_files() {
    if ! $CLEANUP_CORRUPTED; then
        return
    fi

    log_warning "Scanning for corrupted/partial files in $MIRROR_PATH..."

    local found_files
    found_files=$(find "$MIRROR_PATH" -type f \( -name "*.PART" -o -name "*.FAILED" \) -print -delete)

    if [[ -n "$found_files" ]]; then
        log_warning "Removed the following files:"
        echo "$found_files" | while IFS= read -r line; do
            log_warning "  - $line"
        done
    else
        log_info "No corrupted/partial files found."
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 7. SYNC EXECUTION FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Main debmirror execution
run_debmirror() {
    local repo_type="$1"
    local host="$2"
    local root="$3"
    local dists="$4"
    local target_path="$5"

    log_info "--- Starting sync for ${repo_type} (${host}) into '${target_path}' ---"

    local debmirror_cmd=(
        debmirror
        "--progress"
        "--ignore-release-gpg"
        "--keyring=$GPG_KEYRING"
        "--host=$host"
        "--root=$root"
        "--dist=$dists"
        "--section=$SECTIONS"
        "--arch=$ARCH"
        "--method=$SYNC_METHOD"
        "--rsync-extra=none"
        "--diff=none"
    )

    if $USE_PROXY && [[ "$SYNC_METHOD" == "http" ]]; then
        debmirror_cmd+=("--proxy=$PROXY")
    fi

    if $USE_DRY_RUN; then
        debmirror_cmd+=("--dry-run")
    fi

    local output_file="${TEMP_DIR}/debmirror_output_${repo_type}.log"

    log_debug "Executing Debmirror command: ${debmirror_cmd[*]} ${target_path}"

    "${debmirror_cmd[@]}" "$target_path" 2>&1 | tee "$output_file"
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -ne 0 ]] || grep -q -i -E '^(error|fatal):|i/o error|failed to' "$output_file"; then
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
    # Configuration and initialization
    load_configuration_file

    process_arguments "$@"

    trap cleanup_handler EXIT

    initialize_system

    log_info "Starting $SCRIPT_NAME v$SCRIPT_VERSION (PID: $$)"

    # Lock acquisition
    acquire_lock

    # Validation phase
    {
        validate_dependencies &&
        resolve_debian_version &&
        validate_environment
    } || exit 1

    # Prepare sync targets
    local main_releases="${RESOLVED_DEBIAN_VERSION},${RESOLVED_DEBIAN_VERSION}-updates,${RESOLVED_DEBIAN_VERSION}-proposed-updates,${RESOLVED_DEBIAN_VERSION}-backports"
    local security_releases="${RESOLVED_DEBIAN_VERSION}-security"

    # Check for non-free-firmware availability
    if ! curl -sL --fail "http://${MIRROR_HOST}/${MIRROR_ROOT}/dists/${RESOLVED_DEBIAN_VERSION}/non-free-firmware/binary-${ARCH}/Release" &>/dev/null; then
        log_warning "Section 'non-free-firmware' not found for ${RESOLVED_DEBIAN_VERSION}. Removing it from sync."
        SECTIONS=$(echo "$SECTIONS" | sed -e 's/,non-free-firmware//g' -e 's/non-free-firmware,//g' -e 's/non-free-firmware//g')
    fi

    log_info "Targeting main releases: $main_releases"
    if [[ "$main_releases" == *proposed-updates* ]]; then
        log_warning "The 'proposed-updates' repository is included. Use with caution."
    fi
    log_info "Targeting security releases: $security_releases"

    # Pre-sync preparation
    perform_bandwidth_test
    cleanup_corrupted_files

    # Sync execution
    local main_repo_path="${MIRROR_PATH}/${MIRROR_ROOT}"
    local security_repo_path="${MIRROR_PATH}/${MIRROR_SECURITY_ROOT}"
    local original_sync_method=$SYNC_METHOD

    # Main repository sync
    run_debmirror "main_repo" "$MIRROR_HOST" "$MIRROR_ROOT" "$main_releases" "$main_repo_path"

    # Security repository sync
    if ! $SYNC_FAILED; then
        if [[ "$original_sync_method" == "rsync" ]]; then
            log_info "Forcing http method for security repository (rsync is not available there)."
            SYNC_METHOD="http"
        fi
        run_debmirror "security_repo" "$SECURITY_HOST" "$MIRROR_SECURITY_ROOT" "$security_releases" "$security_repo_path"
    else
        log_warning "Skipping security sync due to previous failure in main sync."
    fi

    # Restore original sync method
    SYNC_METHOD=$original_sync_method

    # Final status check
    if $SYNC_FAILED; then
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
