# sentinelscan

*A fast, read-only Linux security scanner (Ubuntu-first).*

`sentinelscan` runs a handful of pragmatic hardening checks and prints:

* a **human-friendly** report (`--pretty`)
* a **machine-readable** report (`--json`)
* an optional **CI gate** (`--fail-on MEDIUM|HIGH`)

It **does not** modify your system.

---

## ✨ What it checks

* **OS & Kernel**

  * Distro / kernel summary, simple EOL heuristic
* **Packages & Updates**

  * Count of pending APT upgrades
  * Count of pending **security** upgrades
* **Firewall**

  * UFW or firewalld status
* **Listening Services**

  * Wide-open sockets via `ss -tulpn` (0.0.0.0 / :: on sensitive ports)
* **SSH Hardening**

  * `/etc/ssh/sshd_config` for risky directives (root login, password auth, etc.)
* **SUID/SGID Binaries**

  * Counts binaries with setuid/setgid in key paths
* **World-writable Paths**

  * Flags world-writable dirs in sensitive locations (`/etc`, `/usr/local/bin`, `~/bin`)
* **Home SSH Permissions**

  * Ensures `~/.ssh` is `700` and private keys are `600`

Each finding includes **risk** (LOW/MEDIUM/HIGH), **evidence**, and **remediation**.

---

## 🚀 Install

### Snap (edge) — once the review is approved

```bash
sudo snap install sentinelscan --classic --edge
```

### Local snap (for testing)

```bash
sudo snap install --dangerous --classic ./sentinelscan_<version>_<arch>.snap
```

> The snap uses **classic** confinement so the scanner can read host files (e.g., `/etc/ssh/sshd_config`), enumerate listeners via `ss`, and invoke host tools like `ufw` and `apt`. The tool is read-only.

---

## 💡 Usage

```bash
# Human-friendly output
sentinelscan --pretty

# JSON report (good for automation)
sentinelscan --json report.json

# CI gate: exit with code 2 if any finding >= MEDIUM
sentinelscan --fail-on MEDIUM
```

> Run with `sudo` for the most complete evidence (e.g., UFW output):
>
> ```bash
> sudo sentinelscan --pretty
> ```

---

## 📦 JSON shape (example)

```json
{
  "results": [
    {
      "check": "Firewall",
      "findings": [
        {
          "id": "FW-UFW",
          "title": "UFW firewall status",
          "risk": "MEDIUM",
          "evidence": "ERROR: You need to be root to run this script",
          "remediation": "If this is a server, enable UFW and restrict inbound ports: `sudo ufw enable` and add allow rules explicitly."
        }
      ]
    }
  ],
  "summary": { "highest_risk": "MEDIUM" }
}
```

---

## 🔧 Development

### Run from source

```bash
python3 security_scanner.py --pretty
python3 security_scanner.py --json out.json --fail-on HIGH
```

### Local virtualenv (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 security_scanner.py --pretty
```

---

## 🧰 Build the snap

### Pack locally (amd64 host)

```bash
snapcraft pack --destructive-mode
# -> produces sentinelscan_<version>_amd64.snap
```

### Remote build (amd64 + arm64)

```bash
snapcraft remote-build --build-for=amd64,arm64
# downloads the .snap artifacts when done
```

### Release to the Snap Store

```bash
# after upload; release revisions to a channel
snapcraft list-revisions sentinelscan
snapcraft release sentinelscan <rev-amd64> edge
snapcraft release sentinelscan <rev-arm64> edge
```

> Classic snaps require **manual review**. In the store listing, include a short justification:
> *“Security auditing requires host-level read access across `/etc`, `/usr/*`, `/proc`, and home `~/.ssh`, plus host tools (`ss`, `ufw`, `apt`). These are not reliably accessible under strict confinement. The app is read-only.”*

---

## 🛡️ Security & Scope

* Read-only: never modifies system state
* Runs on Ubuntu (tested on 24.04 LTS) and other Debian-like systems with APT
* Designed to be **safe to run** in CI and dev environments

---

## 🧪 Exit codes

* `0` – completed, no `--fail-on` threshold breached
* `2` – `--fail-on` threshold met or exceeded (e.g., MEDIUM/HIGH present)
* Other – command execution errors, etc.

---

## 📄 License

Apache-2.0 © 2025 Shashank Sathola

---

## 🙌 Contributing

Issues and PRs are welcome. For substantial changes, please open an issue first to discuss the approach.

---

## 🔗 Links

* Snapcraft recipe: [`snap/snapcraft.yaml`](snap/snapcraft.yaml)
* Source: [https://github.com/shashank381/sentinelscan](https://github.com/shashank381/sentinelscan)
