"""
Setup script that creates shell aliases/functions
to intercept pip install and npm install commands.

Run once: python cli/setup_hooks.py --install
Remove:   python cli/setup_hooks.py --uninstall
"""

import os
import sys
import platform


# Get the absolute path to the installer
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER_PATH = os.path.join(PROJECT_ROOT, "cli", "installer.py")
PYTHON_PATH = sys.executable


# ──────────────────────────────────────────────
# HOOK TEMPLATES
# ──────────────────────────────────────────────

def get_bash_hook():
    r"""
    Generate bash/zsh hook content.
    Uses raw strings to avoid Python escape warnings.
    """
    dollar = "$"  # Store $ in a variable to avoid any escape issues
    d1 = dollar + "1"
    d_at = dollar + "@"

    lines = [
        "",
        "# -- SupplyChainGuard pip interceptor --",
        "scg_pip() {",
        '    if [ "' + d1 + '" = "install" ]; then',
        "        shift",
        '        case "' + d1 + '" in',
        "            -r|--requirement|-e|--editable|-U|--upgrade)",
        '                command pip install "' + d_at + '"',
        "                ;;",
        "            -*)",
        '                command pip install "' + d_at + '"',
        "                ;;",
        "            *)",
        '                echo ""',
        '                echo "  [SCG] SupplyChainGuard intercepted: pip install ' + d_at + '"',
        '                echo ""',
        '                "' + PYTHON_PATH + '" "' + INSTALLER_PATH + '" install "' + d1 + '" -e pypi',
        "                ;;",
        "        esac",
        "    else",
        '        command pip "' + d_at + '"',
        "    fi",
        "}",
        "alias pip='scg_pip'",
        "",
        "# -- SupplyChainGuard npm interceptor --",
        "scg_npm() {",
        '    if [ "' + d1 + '" = "install" ] || [ "' + d1 + '" = "i" ]; then',
        "        shift",
        '        case "' + d1 + '" in',
        "            -g|--global|-D|--save-dev)",
        '                flag="' + d1 + '"',
        "                shift",
        '                echo ""',
        '                echo "  [SCG] SupplyChainGuard intercepted: npm install ' + d_at + '"',
        '                echo ""',
        '                "' + PYTHON_PATH + '" "' + INSTALLER_PATH + '" install "' + d1 + '" -e npm',
        "                ;;",
        "            -*)",
        '                command npm install "' + d_at + '"',
        "                ;;",
        '            "")',
        "                command npm install",
        "                ;;",
        "            *)",
        '                echo ""',
        '                echo "  [SCG] SupplyChainGuard intercepted: npm install ' + d_at + '"',
        '                echo ""',
        '                "' + PYTHON_PATH + '" "' + INSTALLER_PATH + '" install "' + d1 + '" -e npm',
        "                ;;",
        "        esac",
        "    else",
        '        command npm "' + d_at + '"',
        "    fi",
        "}",
        "alias npm='scg_npm'",
        "# -- End SupplyChainGuard --",
        "",
    ]
    return "\n".join(lines)


def get_powershell_hook():
    """
    Generate PowerShell hook content.
    ASCII-safe characters only.
    """
    dollar = "$"
    d_args = dollar + "args"
    d_pkg = dollar + "pkg"

    lines = [
        "",
        "# -- SupplyChainGuard pip interceptor (PowerShell) --",
        "function scg_pip {",
        '    if (' + d_args + '[0] -eq "install") {',
        "        " + d_pkg + " = " + d_args + "[1]",
        '        if (' + d_pkg + ' -and -not ' + d_pkg + '.StartsWith("-")) {',
        '            Write-Host ""',
        '            Write-Host "  [SCG] SupplyChainGuard intercepted: pip install ' + d_pkg + '"',
        '            Write-Host ""',
        '            & "' + PYTHON_PATH + '" "' + INSTALLER_PATH + '" install ' + d_pkg + ' -e pypi',
        "        } else {",
        "            & pip.exe install " + d_args + "[1..(" + d_args + ".Length-1)]",
        "        }",
        "    } else {",
        "        & pip.exe " + d_args,
        "    }",
        "}",
        "Set-Alias -Name pip -Value scg_pip -Scope Global",
        "",
        "# -- SupplyChainGuard npm interceptor (PowerShell) --",
        "function scg_npm {",
        '    if (' + d_args + '[0] -eq "install" -or ' + d_args + '[0] -eq "i") {',
        "        " + d_pkg + " = " + d_args + "[1]",
        '        if (' + d_pkg + ' -and -not ' + d_pkg + '.StartsWith("-")) {',
        '            Write-Host ""',
        '            Write-Host "  [SCG] SupplyChainGuard intercepted: npm install ' + d_pkg + '"',
        '            Write-Host ""',
        '            & "' + PYTHON_PATH + '" "' + INSTALLER_PATH + '" install ' + d_pkg + ' -e npm',
        "        } else {",
        "            & npm.cmd install " + d_args + "[1..(" + d_args + ".Length-1)]",
        "        }",
        "    } else {",
        "        & npm.cmd " + d_args,
        "    }",
        "}",
        "Set-Alias -Name npm -Value scg_npm -Scope Global",
        "# -- End SupplyChainGuard --",
        "",
    ]
    return "\n".join(lines)


# ──────────────────────────────────────────────
# SHELL CONFIG DETECTION
# ──────────────────────────────────────────────

def get_shell_config_path():
    """Determine which shell config file to modify"""
    system = platform.system()

    if system == "Windows":
        home = os.path.expanduser("~")

        # Try modern PowerShell first (PowerShell 7+)
        modern_ps = os.path.join(
            home, "Documents", "PowerShell",
            "Microsoft.PowerShell_profile.ps1"
        )
        if os.path.exists(os.path.dirname(modern_ps)):
            return modern_ps, "powershell"

        # Fall back to Windows PowerShell 5.x
        legacy_ps = os.path.join(
            home, "Documents", "WindowsPowerShell",
            "Microsoft.PowerShell_profile.ps1"
        )
        return legacy_ps, "powershell"

    else:
        shell = os.environ.get("SHELL", "/bin/bash")
        if "zsh" in shell:
            return os.path.expanduser("~/.zshrc"), "bash"
        elif "fish" in shell:
            return os.path.expanduser("~/.config/fish/config.fish"), "fish"
        else:
            return os.path.expanduser("~/.bashrc"), "bash"


# ──────────────────────────────────────────────
# INSTALL
# ──────────────────────────────────────────────

def install_hooks():
    """Install shell hooks to intercept pip/npm"""
    config_path, shell_type = get_shell_config_path()

    print("")
    print("  [SCG] SupplyChainGuard - Shell Hook Setup")
    print("  " + "=" * 50)
    print("  Shell config: " + config_path)
    print("  Shell type:   " + shell_type)
    print("  Python:       " + PYTHON_PATH)
    print("  Installer:    " + INSTALLER_PATH)
    print("  " + "=" * 50)

    # Check if already installed
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
            existing = f.read()
        if "SupplyChainGuard" in existing:
            print("")
            print("  [!] Hooks already installed in " + config_path)
            print("  Run with --uninstall first to reinstall.")
            return

    # Choose hook content
    if shell_type == "powershell":
        hook_content = get_powershell_hook()
    else:
        hook_content = get_bash_hook()

    # Create config directory if needed
    config_dir = os.path.dirname(config_path)
    if config_dir and not os.path.exists(config_dir):
        os.makedirs(config_dir, exist_ok=True)
        print("")
        print("  Created directory: " + config_dir)

    # Write with UTF-8 encoding
    with open(config_path, "a", encoding="utf-8") as f:
        f.write(hook_content)

    print("")
    print("  [OK] Hooks installed successfully!")
    print("")
    print("  What changed:")
    print("    - 'pip install <pkg>' now scans before installing")
    print("    - 'npm install <pkg>' now scans before installing")
    print("")
    print("  To activate, run:")

    if shell_type == "powershell":
        print("    . $PROFILE")
        print("")
        print("  Or if that fails:")
        print('    . "' + config_path + '"')
    else:
        print("    source " + config_path)

    print("")
    print("  Or simply restart your terminal.")
    print("")


# ──────────────────────────────────────────────
# UNINSTALL
# ──────────────────────────────────────────────

def uninstall_hooks():
    """Remove shell hooks"""
    config_path, shell_type = get_shell_config_path()

    if not os.path.exists(config_path):
        print("  Shell config not found: " + config_path)
        return

    with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if "SupplyChainGuard" not in content:
        print("  No SupplyChainGuard hooks found in " + config_path)
        return

    # Remove everything between the markers
    lines = content.split("\n")
    new_lines = []
    skip = False

    for line in lines:
        if "SupplyChainGuard" in line and "interceptor" in line.lower():
            skip = True
            continue
        if "End SupplyChainGuard" in line:
            skip = False
            continue
        if not skip:
            new_lines.append(line)

    # Clean up extra blank lines
    cleaned = "\n".join(new_lines)
    while "\n\n\n" in cleaned:
        cleaned = cleaned.replace("\n\n\n", "\n\n")

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(cleaned)

    print("")
    print("  [OK] Hooks removed from " + config_path)
    print("  Restart your terminal to take effect.")
    print("")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            install_hooks()
        elif sys.argv[1] == "--uninstall":
            uninstall_hooks()
        else:
            print("Usage: python cli/setup_hooks.py --install|--uninstall")
    else:
        print("Usage: python cli/setup_hooks.py --install|--uninstall")