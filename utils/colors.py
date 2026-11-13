"""
Color utilities for consistent colored output across the recon tool.
Provides ANSI color codes and helper functions for colored terminal output.
"""

# Standard colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
MAGENTA = '\033[0;35m'

# Bright/Bold colors
BRIGHT_RED = '\033[1;31m'
BRIGHT_GREEN = '\033[1;32m'
BRIGHT_YELLOW = '\033[1;33m'
BRIGHT_BLUE = '\033[1;34m'
BRIGHT_CYAN = '\033[1;36m'
BRIGHT_MAGENTA = '\033[1;35m'
BRIGHT_WHITE = '\033[1;37m'

# Additional colors
ORANGE = '\033[38;5;208m'
PURPLE = '\033[0;35m'
GRAY = '\033[0;90m'
DARK_GRAY = '\033[1;30m'

# Text formatting
BOLD = '\033[1m'
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'

# Status-specific colors
SUCCESS_COLOR = '\033[1;32m'      # BRIGHT_GREEN
ERROR_COLOR = '\033[1;31m'        # BRIGHT_RED
WARNING_COLOR = '\033[1;33m'      # BRIGHT_YELLOW
INFO_COLOR = '\033[1;34m'         # BRIGHT_BLUE
DEBUG_COLOR = '\033[0;90m'        # GRAY
CRITICAL_COLOR = '\033[1;31m\033[1m'  # BRIGHT_RED + BOLD
NOTICE_COLOR = '\033[1;36m'       # BRIGHT_CYAN
PROGRESS_COLOR = '\033[1;36m'     # BRIGHT_CYAN

# Background colors
SUCCESS_BG = '\033[1;32m\033[7m'   # BRIGHT_GREEN + REVERSE
ERROR_BG = '\033[1;31m\033[7m'     # BRIGHT_RED + REVERSE
WARNING_BG = '\033[1;33m\033[7m'   # BRIGHT_YELLOW + REVERSE

# Text formatting
BOLD = '\033[1m'
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'

# Reset
NC = '\033[0m'  # No Color


# Status-specific color constants
SUCCESS = '\033[1;32m'      # BRIGHT_GREEN
ERROR = '\033[1;31m'        # BRIGHT_RED
WARNING = '\033[1;33m'      # BRIGHT_YELLOW
INFO = '\033[1;34m'         # BRIGHT_BLUE
DEBUG = '\033[0;90m'        # GRAY
CRITICAL = '\033[1;31m\033[1m'  # BRIGHT_RED + BOLD
NOTICE = '\033[1;36m'       # BRIGHT_CYAN
PROGRESS = '\033[1;36m'     # BRIGHT_CYAN

# Background colors
SUCCESS_BG = '\033[1;32m\033[7m'   # BRIGHT_GREEN + REVERSE
ERROR_BG = '\033[1;31m\033[7m'     # BRIGHT_RED + REVERSE
WARNING_BG = '\033[1;33m\033[7m'   # BRIGHT_YELLOW + REVERSE

# Text formatting
BOLD = '\033[1m'
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'

# Reset
NC = '\033[0m'  # No Color


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{NC}"


def bold(text: str) -> str:
    """Make text bold."""
    return f"{BOLD}{text}{NC}"


def dim(text: str) -> str:
    """Make text dim."""
    return f"{DIM}{text}{NC}"


def underline(text: str) -> str:
    """Underline text."""
    return f"{UNDERLINE}{text}{NC}"


def success(text: str) -> str:
    """Format text as success (green)."""
    return f"\033[1;32m{text}{NC}"


def error(text: str) -> str:
    """Format text as error (red)."""
    return f"\033[1;31m{text}{NC}"


def warning(text: str) -> str:
    """Format text as warning (yellow)."""
    return f"\033[1;33m{text}{NC}"


def info(text: str) -> str:
    """Format text as info (blue)."""
    return f"\033[1;34m{text}{NC}"


def debug(text: str) -> str:
    """Format text as debug (gray)."""
    return f"\033[0;90m{text}{NC}"


def critical(text: str) -> str:
    """Format text as critical (bold red)."""
    return f"\033[1;31m\033[1m{text}{NC}"


def notice(text: str) -> str:
    """Format text as notice (cyan)."""
    return f"\033[1;36m{text}{NC}"


def progress(text: str) -> str:
    """Format text as progress (cyan)."""
    return f"\033[1;36m{text}{NC}"


def bold(text: str) -> str:
    """Make text bold."""
    return f"\033[1m{text}{NC}"


def dim(text: str) -> str:
    """Make text dim."""
    return f"\033[2m{text}{NC}"


def underline(text: str) -> str:
    """Underline text."""
    return f"\033[4m{text}{NC}"


def success_box(text: str) -> str:
    """Format text in a success box (green background)."""
    return f"\033[1;32m\033[7m {text} \033[0m"


def error_box(text: str) -> str:
    """Format text in an error box (red background)."""
    return f"\033[1;31m\033[7m {text} \033[0m"


def warning_box(text: str) -> str:
    """Format text in a warning box (yellow background)."""
    return f"\033[1;33m\033[7m {text} \033[0m"


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{NC}"


def print_colored(text: str, color: str) -> None:
    """Print colored text."""
    print(f"{color}{text}{NC}")


def print_success(text: str) -> None:
    """Print success message."""
    print(f"\033[1;32m[SUCCESS]{NC} {text}")


def print_error(text: str) -> None:
    """Print error message."""
    print(f"\033[1;31m[ERROR]{NC} {text}")


def print_warning(text: str) -> None:
    """Print warning message."""
    print(f"\033[1;33m[WARN]{NC} {text}")


def print_info(text: str) -> None:
    """Print info message."""
    print(f"\033[1;34m[INFO]{NC} {text}")


def print_debug(text: str) -> None:
    """Print debug message."""
    print(f"\033[0;90m[DEBUG]{NC} {text}")


def print_critical(text: str) -> None:
    """Print critical message."""
    print(f"\033[1;31m\033[1m[CRITICAL]{NC} {text}")


def print_notice(text: str) -> None:
    """Print notice message."""
    print(f"\033[1;36m[NOTICE]{NC} {text}")


def print_progress(text: str) -> None:
    """Print progress message."""
    print(f"\033[1;36m[PROGRESS]{NC} {text}")


def print_notice(text: str) -> None:
    """Print notice message."""
    print(f"\033[1;36m[NOTICE]{NC} {text}")


def print_success_box(text: str) -> None:
    """Print success message in a box."""
    print(f"\033[1;32m\033[7m {text} \033[0m")


def print_error_box(text: str) -> None:
    """Print error message in a box."""
    print(f"\033[1;31m\033[7m {text} \033[0m")


def print_warning_box(text: str) -> None:
    """Print warning message in a box."""
    print(f"\033[1;33m\033[7m {text} \033[0m")


# Status prefixes for consistent logging
STATUS_PREFIXES = {
    'success': '[SUCCESS]',
    'error': '[ERROR]',
    'warning': '[WARN]',
    'info': '[INFO]',
    'debug': '[DEBUG]',
    'critical': '[CRITICAL]',
    'notice': '[NOTICE]',
    'progress': '[PROGRESS]',
}

STATUS_COLORS = {
    'success': '\033[1;32m',
    'error': '\033[1;31m',
    'warning': '\033[1;33m',
    'info': '\033[1;34m',
    'debug': '\033[0;90m',
    'critical': '\033[1;31m\033[1m',
    'notice': '\033[1;36m',
    'progress': '\033[1;36m',
}


def print_status(status: str, message: str) -> None:
    """Print a status message with appropriate color."""
    prefix = STATUS_PREFIXES.get(status, '[INFO]')
    color = STATUS_COLORS.get(status, '\033[1;34m')
    print(f"{color}{prefix}{NC} {message}")


def print_colored(text: str, color: str) -> None:
    """Print text with specified color."""
    print(f"{color}{text}{NC}")


def print_bold(text: str) -> None:
    """Print bold text."""
    print(f"\033[1m{text}{NC}")


def print_dim(text: str) -> None:
    """Print dim text."""
    print(f"\033[2m{text}{NC}")


def print_underline(text: str) -> None:
    """Print underlined text."""
    print(f"\033[4m{text}{NC}")


def print_success_box(text: str) -> None:
    """Print success message in a box."""
    print(f"\033[1;32m\033[7m {text} \033[0m")


def print_error_box(text: str) -> None:
    """Print error message in a box."""
    print(f"\033[1;31m\033[7m {text} \033[0m")


def print_warning_box(text: str) -> None:
    """Print warning message in a box."""
    print(f"\033[1;33m\033[7m {text} \033[0m")