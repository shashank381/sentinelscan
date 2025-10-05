#!/usr/bin/env python3
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional

# -----------------------------
# Utility helpers
# -----------------------------

def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]} not found")

ANSI = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "bold": "\033[1m",
}

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

@dataclass
class Finding:
    id: str
    title: str
    risk: str  # LOW | MEDIUM | HIGH
    evidence: str
    remediation: str

@dataclass
class CheckResult:
    check: str
    findings: List[Finding]

# -----------------------------
# Check registry
# -----------------------------
CHECKS = []

def register(fn):
    CHECKS.append(fn)
    return fn

# -----------------------------
# Individual checks
# -----------------------------

@register
def check_os_kernel() -> CheckResult:
    """Collect distro + kernel; flag EOL Ubuntu if detectable."""
    findings = []
    lsb = run_cmd(["lsb_release", "-ds"]) if shutil.which("lsb_release") else run_cmd(["cat", "/etc/os-release"])
    kernel = run_cmd(["uname", "-r"]).stdout.strip()
    distro_line = lsb.stdout.strip().splitlines()[0] if lsb.stdout else platform.platform()

    # Very light heuristic for Ubuntu EOL versions (extend as needed)
    eol_versions = ["16.04", "18.10", "21.04", "21.10"]
    risk = "LOW"
    for v in eol_versions:
        if v in distro_line:
            risk = "HIGH"
            findings.append(Finding(
                id="OS-EOL",
                title="Operating system may be End-of-Life",
                risk=risk,
                evidence=f"Detected distro/version: {distro_line}",
                remediation="Upgrade to a supported Ubuntu release (e.g., 22.04 LTS or 24.04 LTS).",
            ))
            break

    if not findings:
        findings.append(Finding(
            id="OS-INFO",
            title="OS and kernel information",
            risk="LOW",
            evidence=f"Distro: {distro_line}; Kernel: {kernel}",
            remediation="Keep kernel and packages updated; consider LTS releases for servers.",
        ))
    return CheckResult(check="OS & Kernel", findings=findings)

@register
def check_packages() -> CheckResult:
    findings = []
    # Try apt first
    if shutil.which("apt"):
        # `apt -s upgrade` simulates and prints upgradable packages
        cp = run_cmd(["bash", "-lc", "apt -s upgrade 2>/dev/null | grep -Eo '^[0-9]+ upgraded' -m1 | awk '{print $1}'"])
        try:
            count = int(cp.stdout.strip() or 0)
        except ValueError:
            count = 0
        risk = "LOW" if count == 0 else ("MEDIUM" if count < 50 else "HIGH")
        findings.append(Finding(
            id="PKG-UPGRADABLE",
            title="Pending package upgrades",
            risk=risk,
            evidence=f"Upgradable packages: {count}",
            remediation="Run `sudo apt update && sudo apt upgrade -y` or apply unattended-upgrades.",
        ))
    else:
        findings.append(Finding(
            id="PKG-UNKNOWN",
            title="Package manager not detected",
            risk="LOW",
            evidence="No apt/dnf/yum detected in PATH.",
            remediation="Ensure system uses a supported package manager and keep it updated.",
        ))
    return CheckResult(check="Packages & Updates", findings=findings)

@register
def check_firewall() -> CheckResult:
    findings = []
    if shutil.which("ufw"):
        cp = run_cmd(["ufw", "status", "verbose"])
        text = (cp.stdout + "\n" + cp.stderr).strip()
        enabled = re.search(r"Status:\s*active", text, re.IGNORECASE) is not None
        first_line = next((ln for ln in text.splitlines() if ln.strip()), "no output")
        findings.append(Finding(
            id="FW-UFW",
            title="UFW firewall status",
            risk="LOW" if enabled else "MEDIUM",
            evidence=first_line,
            remediation="If this is a server, enable UFW and restrict inbound ports: `sudo ufw enable` and add allow rules explicitly."
        ))
    elif shutil.which("firewall-cmd"):
        cp = run_cmd(["firewall-cmd", "--state"])
        state = (cp.stdout + cp.stderr).strip()
        findings.append(Finding("FW-FIREWALLD", "firewalld status",
                                "LOW" if state == "running" else "MEDIUM",
                                f"firewalld state: {state or 'unknown'}",
                                "Start and configure firewalld or use UFW on Ubuntu."))
    else:
        findings.append(Finding("FW-NONE", "No firewall tool detected", "MEDIUM",
                                "Neither ufw nor firewalld is installed.",
                                "Install and enable UFW (`sudo apt install ufw && sudo ufw enable`) and define allow-lists."))
    return CheckResult(check="Firewall", findings=findings)

@register
def check_listeners() -> CheckResult:
    findings = []
    if shutil.which("ss"):
        out = run_cmd(["bash", "-lc", "ss -tulpn | awk 'NR>1 {print $1, $5, $7}'"]).stdout
        listeners = [line.strip() for line in out.splitlines() if line.strip()]
        high = []
        for line in listeners:
            # mark high risk if listening on 0.0.0.0 or ::: on sensitive ports
            if re.search(r"(0\.0\.0\.0|::):", line):
                if re.search(r":(22|23|21|25|445|3389|3306|5432|6379)\b", line):
                    high.append(line)
        risk = "LOW" if not high else ("MEDIUM" if len(high) < 3 else "HIGH")
        evidence = f"Total listeners: {len(listeners)}; Wide-open: {len(high)}"
        remediation = "Bind services to localhost or specific interfaces; restrict via firewall; close unused daemons."
        findings.append(Finding("NET-LISTEN", "Network listeners", risk, evidence, remediation))
    else:
        findings.append(Finding("NET-SS-NOTFOUND", "Cannot enumerate listeners (ss missing)", "LOW", "`ss` not in PATH", "Install iproute2 to provide `ss`."))
    return CheckResult(check="Listening Services", findings=findings)

@register
def check_ssh_config() -> CheckResult:
    findings = []
    cfg = Path("/etc/ssh/sshd_config")
    if cfg.exists():
        content = cfg.read_text(errors="ignore")
        root_login = re.search(r"^\s*PermitRootLogin\s+yes", content, re.MULTILINE)
        pass_auth = re.search(r"^\s*PasswordAuthentication\s+yes", content, re.MULTILINE)
        if root_login:
            findings.append(Finding("SSH-ROOT", "Root SSH login enabled", "HIGH", "PermitRootLogin yes", "Set `PermitRootLogin no` and reload sshd."))
        if pass_auth:
            findings.append(Finding("SSH-PASSAUTH", "Password authentication enabled", "MEDIUM", "PasswordAuthentication yes", "Use key-based auth; set `PasswordAuthentication no`."))
        if not findings:
            findings.append(Finding("SSH-OK", "SSHD hardening looks okay", "LOW", "No risky directives detected", "Consider Fail2Ban and key-only auth."))
    else:
        findings.append(Finding("SSH-NOCFG", "sshd_config not found", "LOW", str(cfg), "Ensure OpenSSH server is installed and configured securely."))
    return CheckResult(check="SSH Hardening", findings=findings)

@register
def check_suid() -> CheckResult:
    findings = []
    paths = ["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"]
    cmd = ["bash", "-lc", "find %s -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null" % " ".join(paths)]
    out = run_cmd(cmd).stdout
    suids = [p for p in out.splitlines() if p]
    # Flag if unusually many SUID/SGID binaries
    risk = "LOW" if len(suids) <= 40 else ("MEDIUM" if len(suids) <= 120 else "HIGH")
    findings.append(Finding("FS-SUID", "SUID/SGID binaries present", risk, f"Count: {len(suids)}", "Review necessity; remove SUID where possible; monitor for anomalies."))
    return CheckResult(check="SUID/SGID Binaries", findings=findings)

@register
def check_world_writable() -> CheckResult:
    findings = []
    home_bin = str(Path.home() / "bin")
    targets = ["/etc", "/usr/local/bin", home_bin]
    cmd = ["bash", "-lc", "for d in %s; do [ -d \"$d\" ] && find \"$d\" -xdev -type d -perm -0002 -printf '%%p\n'; done 2>/dev/null" % " ".join(targets)]
    out = run_cmd(cmd).stdout
    dirs = [d for d in out.splitlines() if d]
    if dirs:
        findings.append(Finding("FS-WORLDWRITABLE", "World-writable directories found", "HIGH", "\n".join(dirs[:10]) + ("\n..." if len(dirs) > 10 else ""), "Remove world-writable bit or tighten ownership/permissions."))
    else:
        findings.append(Finding("FS-WORLDWRITABLE-OK", "No world-writable dirs in sensitive paths", "LOW", "Checked /etc, /usr/local/bin, ~/bin", "Maintain least-privilege permissions."))
    return CheckResult(check="World-writable Paths", findings=findings)


@register
def check_security_updates() -> CheckResult:
    findings = []
    # Count upgradable packages that are from the security pocket
    cp = run_cmd(["bash","-lc","apt list --upgradable 2>/dev/null | grep -cE '\\-security' || true"])
    try: sec_count = int((cp.stdout or "0").strip())
    except ValueError: sec_count = 0
    risk = "LOW" if sec_count == 0 else ("MEDIUM" if sec_count < 10 else "HIGH")
    findings.append(Finding(
        id="SEC-UPDATES",
        title="Security updates available",
        risk=risk,
        evidence=f"Upgradable security packages: {sec_count}",
        remediation="Run `sudo apt update && sudo apt upgrade -y` and consider unattended-upgrades for automatic security patches."
    ))
    return CheckResult(check="Security Updates", findings=findings)

@register
def check_home_ssh_perms() -> CheckResult:
    findings = []
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.exists():
        # directory should be 700
        st = ssh_dir.stat().st_mode & 0o777
        if st != 0o700:
            findings.append(Finding("HOME-SSH-DIR", "~/.ssh permissions are not 700", "MEDIUM", f"Mode: {oct(st)}", "Run `chmod 700 ~/.ssh`."))
        for key in ["id_rsa", "id_ed25519"]:
            p = ssh_dir / key
            if p.exists():
                st = p.stat().st_mode & 0o777
                if st != 0o600:
                    findings.append(Finding("HOME-SSH-KEY", f"Private key {key} permissions not 600", "HIGH", f"Mode: {oct(st)}", f"Run `chmod 600 ~/.ssh/{key}`."))
    else:
        findings.append(Finding("HOME-SSH-MISSING", "~/.ssh not present", "LOW", str(ssh_dir), "Create ~/.ssh with 700 and keys with 600 when needed."))
    if not findings and ssh_dir.exists():
        findings.append(Finding("HOME-SSH-OK", "Home SSH Permissions look good", "LOW", "~/.ssh present and restrictive (700 dir, 600 keys)", "Keep strict permissions."))
    return CheckResult(check="Home SSH Permissions", findings=findings)

# -----------------------------
# Rendering & CLI
# -----------------------------

def colorize(s: str, color: Optional[str], use_color: bool) -> str:
    if not use_color or color is None:
        return s
    return f"{ANSI[color]}{s}{ANSI['reset']}"

def render_pretty(results: List[CheckResult], use_color: bool = True) -> str:
    lines = []
    for res in results:
        lines.append("\n" + ("== " + res.check + " =="))
        for f in res.findings:
            col = "green" if f.risk == "LOW" else ("yellow" if f.risk == "MEDIUM" else "red")
            lines.append(f"- {colorize(f.risk, col, use_color)} | {f.title}")
            lines.append(f"  Evidence: {f.evidence}")
            lines.append(f"  Remediation: {f.remediation}")
    return "\n".join(lines)

def highest_risk(results: List[CheckResult]) -> str:
    max_level = 0
    for r in results:
        for f in r.findings:
            max_level = max(max_level, LEVEL_ORDER.get(f.risk, 0))
    for k, v in LEVEL_ORDER.items():
        if v == max_level:
            return k
    return "LOW"

def main():
    ap = argparse.ArgumentParser(description="UbuntuGuard — Linux security scanner (MVP)")
    ap.add_argument("--json", help="Write JSON results to file path")
    ap.add_argument("--pretty", action="store_true", help="Print human-readable report")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH"], help="Exit nonzero if >= level is found")
    args = ap.parse_args()

    results = [fn() for fn in CHECKS]

    if args.pretty or not args.json:
        print(render_pretty(results, use_color=not args.no_color))

    if args.json:
        payload = {
            "results": [
                {"check": r.check, "findings": [asdict(f) for f in r.findings]} for r in results
            ],
            "summary": {"highest_risk": highest_risk(results)},
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        print(f"\nJSON written to {args.json}")

    # Determine exit code for CI
    if args.fail_on:
        target = LEVEL_ORDER[args.fail_on]
        level = LEVEL_ORDER[highest_risk(results)]
        if level >= target:
            raise SystemExit(2)

if __name__ == "__main__":
    main()
