#!/bin/bash
# Recon Tool - Interactive Menu Interface
# A modular reconnaissance toolkit for information gathering

set -euo pipefail

# Colors for output
# Standard colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'

# Bright/Bold colors
BRIGHT_RED='\033[1;31m'
BRIGHT_GREEN='\033[1;32m'
BRIGHT_YELLOW='\033[1;33m'
BRIGHT_BLUE='\033[1;34m'
BRIGHT_CYAN='\033[1;36m'
BRIGHT_MAGENTA='\033[1;35m'
BRIGHT_WHITE='\033[1;37m'

# Additional colors
ORANGE='\033[38;5;208m'
PURPLE='\033[0;35m'
GRAY='\033[0;90m'
DARK_GRAY='\033[1;30m'

# Text formatting
BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'

# Status-specific colors
SUCCESS_COLOR="${BRIGHT_GREEN}"
ERROR_COLOR="${BRIGHT_RED}"
WARNING_COLOR="${BRIGHT_YELLOW}"
INFO_COLOR="${BRIGHT_BLUE}"
DEBUG_COLOR="${GRAY}"
CRITICAL_COLOR="${BRIGHT_RED}${BOLD}"
NOTICE_COLOR="${BRIGHT_CYAN}"
PROGRESS_COLOR="${BRIGHT_CYAN}"
SUCCESS_BG="${BRIGHT_GREEN}${REVERSE}"
ERROR_BG="${BRIGHT_RED}${REVERSE}"
WARNING_BG="${BRIGHT_YELLOW}${REVERSE}"

NC='\033[0m' # No Color

# Project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/venv"
REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"
MAIN_SCRIPT="$PROJECT_DIR/main.py"
CONFIG_FILE="$PROJECT_DIR/config.yaml"

# Global variables
TARGET=""
MODULE=""
OUTPUT_FILE=""
OUTPUT_FORMAT="json"
CONFIG_PATH=""
STEALTH_ENABLED=true
EXTRA_ARGS=()

# ============================================
# Utility Functions
# ============================================

print_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    RECON TOOL v1.0.0                          ║${NC}"
    echo -e "${CYAN}║         Modular Reconnaissance Toolkit                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo -e "${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ $1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}"
}

print_info() {
    echo -e "${INFO_COLOR}[INFO]${NC} $1"
}

print_success() {
    echo -e "${SUCCESS_COLOR}[SUCCESS]${NC} $1"
}

print_warn() {
    echo -e "${WARNING_COLOR}[WARN]${NC} $1"
}

print_error() {
    echo -e "${ERROR_COLOR}[ERROR]${NC} $1"
}

print_critical() {
    echo -e "${CRITICAL_COLOR}[CRITICAL]${NC} $1"
}

print_notice() {
    echo -e "${NOTICE_COLOR}[NOTICE]${NC} $1"
}

print_debug() {
    echo -e "${DEBUG_COLOR}[DEBUG]${NC} $1"
}

print_progress() {
    echo -e "${PROGRESS_COLOR}[PROGRESS]${NC} $1"
}

# Additional colored output helpers
print_colored() {
    local color=$1
    local text=$2
    echo -e "${color}${text}${NC}"
}

print_bold() {
    echo -e "${BOLD}$1${NC}"
}

print_dim() {
    echo -e "${DIM}$1${NC}"
}

print_underline() {
    echo -e "${UNDERLINE}$1${NC}"
}

# Status box functions
print_success_box() {
    echo -e "${SUCCESS_BG} $1 ${NC}"
}

print_error_box() {
    echo -e "${ERROR_BG} $1 ${NC}"
}

print_warning_box() {
    echo -e "${WARNING_BG} $1 ${NC}"
}

print_prompt() {
    echo -ne "${CYAN}$1${NC}"
}

# ============================================
# Dependency Management
# ============================================

check_python_version() {
    local required_version="3.8"
    local current_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_info "Python version: $current_version ✓"
        return 0
    else
        print_error "Python 3.8+ required. Current: $current_version"
        return 1
    fi
}

check_venv() {
    if [[ -d "$VENV_DIR" ]] && [[ -f "$VENV_DIR/bin/activate" ]]; then
        return 0
    else
        return 1
    fi
}

activate_venv() {
    if check_venv; then
        source "$VENV_DIR/bin/activate"
        print_info "Virtual environment activated"
        return 0
    else
        print_warn "Virtual environment not found"
        return 1
    fi
}

create_venv() {
    print_info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    print_info "Virtual environment created"
}

check_dependencies() {
    local missing=()
    
    # Determine which Python to use
    local python_cmd="python3"
    if check_venv; then
        python_cmd="$VENV_DIR/bin/python"
    fi
    
    # Check core dependencies
    local deps=("aiohttp" "dnspython" "rich" "pyyaml" "click" "requests" "dnspython" "python-nmap" "python-whois" "pyopenssl" "cryptography" "aiohttp" "asyncio-throttle" "packaging" "github3.py" "hunter-sdk" "python-linkedin")
    
    for dep in "${deps[@]}"; do
        if ! $python_cmd -c "import ${dep//-/_}" 2>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    # Check nmap binary
    if ! command -v nmap &> /dev/null; then
        missing+=("nmap (system package)")
    fi
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    else
        echo "${missing[@]}"
        return 1
    fi
}

install_dependencies() {
    print_section "Installing Dependencies"
    
    if ! check_venv; then
        create_venv
    fi
    
    activate_venv
    
    print_info "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r "$REQUIREMENTS_FILE"
    
    # Check nmap
    if ! command -v nmap &> /dev/null; then
        print_warn "nmap not found. Please install nmap:"
        echo "  Ubuntu/Debian: sudo apt install nmap"
        echo "  CentOS/RHEL: sudo yum install nmap"
        echo "  macOS: brew install nmap"
    fi
    
    print_info "Dependencies installed successfully"
}

check_and_install_deps() {
    print_section "Checking Dependencies"
    
    if ! check_python_version; then
        return 1
    fi
    
    local missing=$(check_dependencies)
    if [[ $? -eq 0 ]]; then
        print_info "All dependencies satisfied ✓"
        return 0
    fi
    
    print_warn "Missing dependencies: $missing"
    echo ""
    print_prompt "Install missing dependencies? (y/n): "
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        install_dependencies
        return 0
    else
        print_error "Dependencies not installed. Exiting."
        return 1
    fi
}

# ============================================
# Module Execution Functions
# ============================================

run_module() {
    local module=$1
    local target=$2
    local extra_args=("${@:3}")
    
    local cmd="python3 $MAIN_SCRIPT $target --$module"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        cmd="$cmd -o $OUTPUT_FILE"
    fi
    
    if [[ -n "$OUTPUT_FORMAT" && "$OUTPUT_FORMAT" != "json" ]]; then
        cmd="$cmd -f $OUTPUT_FORMAT"
    fi
    
    if [[ -n "$CONFIG_PATH" ]]; then
        cmd="$cmd -c $CONFIG_PATH"
    fi
    
    if [[ "$STEALTH_ENABLED" == "false" ]]; then
        cmd="$cmd --no-stealth"
    fi
    
    for arg in "${extra_args[@]}"; do
        cmd="$cmd $arg"
    done
    
    print_info "Running: $cmd"
    echo ""
    eval $cmd
}

run_all_modules() {
    local target=$1
    local extra_args=("${@:2}")
    
    local cmd="python3 $MAIN_SCRIPT $target"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        cmd="$cmd -o $OUTPUT_FILE"
    fi
    
    if [[ -n "$OUTPUT_FORMAT" && "$OUTPUT_FORMAT" != "json" ]]; then
        cmd="$cmd -f $OUTPUT_FORMAT"
    fi
    
    if [[ -n "$CONFIG_PATH" ]]; then
        cmd="$cmd -c $CONFIG_PATH"
    fi
    
    if [[ "$STEALTH_ENABLED" == "false" ]]; then
        cmd="$cmd --no-stealth"
    fi
    
    for arg in "${extra_args[@]}"; do
        cmd="$cmd $arg"
    done
    
    print_info "Running all modules: $cmd"
    echo ""
    eval $cmd
}

# ============================================
# Configuration Functions
# ============================================

show_config() {
    print_section "Current Configuration"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        cat "$CONFIG_FILE"
    else
        print_warn "Config file not found: $CONFIG_FILE"
    fi
}

edit_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        ${EDITOR:-nano} "$CONFIG_FILE"
    else
        print_warn "Config file not found: $CONFIG_FILE"
    fi
}

create_default_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_info "Creating default config.yaml..."
        # Config is already created by the tool
    fi
}

# ============================================
# Menu Functions
# ============================================

show_main_menu() {
    print_header
    echo -e "${MAGENTA}Main Menu:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC}  Run All Modules"
    echo -e "  ${GREEN}2)${NC}  Run Specific Module"
    echo -e "  ${GREEN}3)${NC}  Configure Target & Options"
    echo -e "  ${GREEN}4)${NC}  Dependency Management"
    echo -e "  ${GREEN}5)${NC}  Configuration"
    echo -e "  ${GREEN}6)${NC}  Auto-Update Check"
    echo -e "  ${GREEN}7)${NC}  Help & Documentation"
    echo -e "  ${RED}0)${NC}  Exit"
    echo ""
}

show_module_menu() {
    print_section "Select Module"
    echo ""
    echo -e "  ${GREEN}1)${NC}  Subdomain Enumeration        (--subdomain)"
    echo -e "  ${GREEN}2)${NC}  Port Scanning                (--portscan)"
    echo -e "  ${GREEN}3)${NC}  DNS Enumeration              (--dns)"
    echo -e "  ${GREEN}4)${NC}  HTTP Reconnaissance         (--http)"
    echo -e "  ${GREEN}5)${NC}  SSL/TLS Analysis            (--ssl)"
    echo -e "  ${GREEN}6)${NC}  Directory/File Enumeration   (--dir)"
    echo -e "  ${GREEN}7)${NC}  Technology Fingerprinting    (--tech)"
    echo -e "  ${GREEN}8)${NC}  Email Harvesting            (--email)"
    echo -e "  ${GREEN}9)${NC}  Employee Enumeration        (--employee)"
    echo -e "  ${GREEN}10)${NC} Username Enumeration        (--username)"
    echo -e "  ${GREEN}11)${NC} Document Intelligence       (--docs)"
    echo -e "  ${GREEN}12)${NC} GitHub/GitLab Recon         (--github)"
    echo -e "  ${GREEN}13)${NC} Breach Intelligence         (--breach)"
    echo -e "  ${GREEN}14)${NC} Auto-Update Check           (--update)"
    echo -e "  ${GREEN}15)${NC} Run ALL Modules"
    echo -e "  ${RED}0)${NC}  Back to Main Menu"
    echo ""
}

show_config_menu() {
    print_section "Configuration Menu"
    echo ""
    echo -e "  ${GREEN}1)${NC}  View Current Config"
    echo -e "  ${GREEN}2)${NC}  Edit Config (nano)"
    echo -e "  ${GREEN}3)${NC}  Reset to Default"
    echo -e "  ${GREEN}4)${NC}  Set Target Domain"
    echo -e "  ${GREEN}5)${NC}  Set Output Format"
    echo -e "  ${GREEN}6)${NC}  Set Output File"
    echo -e "  ${GREEN}7)${NC}  Toggle Stealth Mode"
    echo -e "  ${RED}0)${NC}  Back to Main Menu"
    echo ""
}

show_dep_menu() {
    print_section "Dependency Management"
    echo ""
    echo -e "  ${GREEN}1)${NC}  Check Dependencies"
    echo -e "  ${GREEN}2)${NC}  Install/Update All Dependencies"
    echo -e "  ${GREEN}3)${NC}  Create Virtual Environment"
    echo -e "  ${GREEN}4)${NC}  Show Current Environment"
    echo -e "  ${GREEN}5)${NC}  Check for Updates"
    echo -e "  ${RED}0)${NC}  Back to Main Menu"
    echo ""
}

# ============================================
# Input Functions
# ============================================

get_target() {
    print_prompt "Enter target domain/IP: "
    read -r TARGET
    if [[ -z "$TARGET" ]]; then
        print_error "Target cannot be empty"
        return 1
    fi
    return 0
}

get_output_format() {
    print_prompt "Output format (json/csv/txt/table/tree) [json]: "
    read -r fmt
    OUTPUT_FORMAT=${fmt:-json}
}

get_output_file() {
    print_prompt "Output file path (optional): "
    read -r OUTPUT_FILE
}

get_config_path() {
    print_prompt "Config file path [config.yaml]: "
    read -r CONFIG_PATH
    CONFIG_PATH=${CONFIG_PATH:-config.yaml}
}

get_extra_args() {
    print_prompt "Extra arguments (optional): "
    read -r line
    EXTRA_ARGS=($line)
}

# ============================================
# Module Execution Wrappers
# ============================================

run_subdomain() {
    if get_target; then
        get_extra_args
        run_module "subdomain" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_portscan() {
    if get_target; then
        get_extra_args
        run_module "portscan" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_dns() {
    if get_target; then
        get_extra_args
        run_module "dns" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_http() {
    if get_target; then
        get_extra_args
        run_module "http" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_ssl() {
    if get_target; then
        get_extra_args
        run_module "ssl" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_dir() {
    if get_target; then
        get_extra_args
        run_module "dir" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_tech() {
    if get_target; then
        get_extra_args
        run_module "tech" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_email() {
    if get_target; then
        get_extra_args
        run_module "email" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_employee() {
    if get_target; then
        get_extra_args
        run_module "employee" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_username() {
    if get_target; then
        get_extra_args
        run_module "username" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_docs() {
    if get_target; then
        get_extra_args
        run_module "docs" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_github() {
    if get_target; then
        get_extra_args
        run_module "github" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_breach() {
    if get_target; then
        get_extra_args
        run_module "breach" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_update() {
    if get_target; then
        get_extra_args
        run_module "update" "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

run_all() {
    if get_target; then
        get_extra_args
        run_all_modules "$TARGET" "${EXTRA_ARGS[@]}"
    fi
}

# ============================================
# Main Loop
# ============================================

main_loop() {
    # Initial dependency check
    if ! check_and_install_deps; then
        exit 1
    fi
    
    # Activate venv if exists
    if check_venv; then
        activate_venv
    fi
    
    while true; do
        show_main_menu
        print_prompt "Select option [0-7]: "
        read -r choice
        
        case $choice in
            1) run_all ;;
            2) module_menu ;;
            3) config_target_menu ;;
            4) dep_menu ;;
            5) config_menu ;;
            6) check_updates ;;
            7) show_help ;;
            0) 
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option"
                sleep 1
                ;;
        esac
        
        echo ""
        print_prompt "Press Enter to continue..."
        read -r
    done
}

module_menu() {
    while true; do
        show_module_menu
        print_prompt "Select module [0-15]: "
        read -r choice
        
        case $choice in
            1) run_subdomain ;;
            2) run_portscan ;;
            3) run_dns ;;
            4) run_http ;;
            5) run_ssl ;;
            6) run_dir ;;
            7) run_tech ;;
            8) run_email ;;
            9) run_employee ;;
            10) run_username ;;
            10) run_docs ;;
            11) run_github ;;
            12) run_breach ;;
            13) run_update ;;
            14) run_all ;;
            0) return ;;
            *)
                print_error "Invalid option"
                sleep 1
                ;;
        esac
        
        echo ""
        print_prompt "Press Enter to continue..."
        read -r
    done
}

config_target_menu() {
    while true; do
        print_section "Target & Options Configuration"
        echo ""
        echo -e "  Current Target: ${YELLOW}${TARGET:-Not set}${NC}"
        echo -e "  Output Format: ${YELLOW}${OUTPUT_FORMAT}${NC}"
        echo -e "  Output File: ${YELLOW}${OUTPUT_FILE:-None}${NC}"
        echo -e "  Config File: ${YELLOW}${CONFIG_PATH:-config.yaml}${NC}"
        echo -e "  Stealth Mode: ${YELLOW}${STEALTH_ENABLED}${NC}"
        echo ""
        echo -e "  ${GREEN}1)${NC}  Set Target Domain/IP"
        echo -e "  ${GREEN}2)${NC}  Set Output Format"
        echo -e "  ${GREEN}3)${NC}  Set Output File"
        echo -e "  ${GREEN}4)${NC}  Set Config File"
        echo -e "  ${GREEN}5)${NC}  Toggle Stealth Mode"
        echo -e "  ${GREEN}6)${NC}  Set Extra Arguments"
        echo -e "  ${RED}0)${NC}  Back"
        echo ""
        
        print_prompt "Select option [0-6]: "
        read -r choice
        
        case $choice in
            1) get_target ;;
            2) get_output_format ;;
            3) get_output_file ;;
            4) get_config_path ;;
            5) 
                if [[ "$STEALTH_ENABLED" == "true" ]]; then
                    STEALTH_ENABLED=false
                    print_info "Stealth mode disabled"
                else
                    STEALTH_ENABLED=true
                    print_info "Stealth mode enabled"
                fi
                ;;
            6) get_extra_args ;;
            0) return ;;
            *) print_error "Invalid option" ;;
        esac
    done
}

dep_menu() {
    while true; do
        show_dep_menu
        print_prompt "Select option [0-5]: "
        read -r choice
        
        case $choice in
            1) 
                print_section "Dependency Check"
                missing=$(check_dependencies)
                if [[ $? -eq 0 ]]; then
                    print_info "All dependencies satisfied ✓"
                else
                    print_warn "Missing: $missing"
                fi
                ;;
            2) install_dependencies ;;
            3) 
                print_info "Creating virtual environment..."
                create_venv
                ;;
            4) 
                print_section "Environment Info"
                echo "Python: $(python3 --version)"
                echo "Venv: $([ -d "$VENV_DIR" ] && echo "Active" || echo "Not created")"
                if check_venv; then
                    source "$VENV_DIR/bin/activate"
                    echo "Pip: $(pip --version)"
                    pip list | grep -E "aiohttp|dnspython|rich|pyyaml|click|requests|nmap|whois|pyopenssl|cryptography|aiohttp|asyncio-throttle|packaging|github3|hunter|linkedin"
                fi
                ;;
            5) check_updates ;;
            0) return ;;
            *) print_error "Invalid option" ;;
        esac
        
        echo ""
        print_prompt "Press Enter to continue..."
        read -r
    done
}

config_menu() {
    while true; do
        show_config_menu
        print_prompt "Select option [0-7]: "
        read -r choice
        
        case $choice in
            1) show_config ;;
            2) edit_config ;;
            3) 
                print_warn "This will reset config to defaults. Continue? (y/n)"
                read -r confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    rm -f "$CONFIG_FILE"
                    print_info "Config reset to defaults"
                fi
                ;;
            4) get_target ;;
            5) get_output_format ;;
            6) get_output_file ;;
            7) 
                if [[ "$STEALTH_ENABLED" == "true" ]]; then
                    STEALTH_ENABLED=false
                    print_info "Stealth mode disabled"
                else
                    STEALTH_ENABLED=true
                    print_info "Stealth mode enabled"
                fi
                ;;
            0) return ;;
            *) print_error "Invalid option" ;;
        esac
        
        echo ""
        print_prompt "Press Enter to continue..."
        read -r
    done
}

check_updates() {
    print_section "Checking for Updates"
    python3 "$MAIN_SCRIPT" --update --check 2>/dev/null || python3 -m modules.auto_update --check
}

show_help() {
    print_section "Help & Documentation"
    echo ""
    echo "Recon Tool - Modular Reconnaissance Toolkit"
    echo ""
    echo "Usage:"
    echo "  ./recon.sh                    # Interactive menu"
    echo "  python3 main.py <target>      # Direct module execution"
    echo ""
    echo "Modules:"
    echo "  --subdomain     Subdomain enumeration (15+ sources)"
    echo "  --portscan      Port scanning (nmap + socket)"
    echo "  --dns           DNS enumeration (records + zone transfer)"
    echo "  --http          HTTP recon (headers, tech, CDN/WAF)"
    echo "  --ssl           SSL/TLS analysis (certs, CT logs, vulns)"
    echo "  --dir           Directory/file enumeration"
    echo "  --tech          Technology fingerprinting (80+ techs)"
    echo "  --email         Email harvesting (Hunter, GitHub, WHOIS)"
    echo "  --employee      Employee enumeration (GitHub, LinkedIn)"
    echo "  --username      Username enumeration (18 platforms)"
    echo "  --docs          Document intelligence (PDF, Office, EXIF)"
    echo "  --github        GitHub/GitLab recon (secrets, contributors)"
    echo "  --breach        Breach intelligence (HIBP, DeHashed, LeakCheck)"
    echo "  --update        Auto-update check"
    echo ""
    echo "Options:"
    echo "  -o, --output    Output file path"
    echo "  -f, --format    Output format (json/csv/txt/table/tree)"
    echo "  -c, --config    Config file path"
    echo "  --no-stealth    Disable stealth mode"
    echo ""
    echo "Config: config.yaml"
    echo "Docs: README.md"
    echo "Roadmap: ROADMAP.md"
    echo ""
}

# ============================================
# Entry Point
# ============================================

# Parse command line arguments for direct module execution
if [[ $# -gt 0 ]] && [[ "$1" != "--menu" ]]; then
    # Direct module execution mode (original behavior)
    # Check dependencies first
    if ! check_and_install_deps; then
        print_error "Dependencies not satisfied. Run './recon.sh' and select option 4 to install dependencies."
        exit 1
    fi
    
    # Activate venv if exists
    if check_venv; then
        activate_venv
    fi
    
    # Direct module execution mode (original behavior)
    python3 "$MAIN_SCRIPT" "$@"
    exit $?
fi

# Interactive menu mode
main_loop