# Contributing to Wiflux

Thank you for your interest in improving Wiflux. This project welcomes bug reports, documentation improvements, and pull requests.

## Before you contribute

- Use Wiflux only for **authorized** security testing.
- Do not submit exploits or techniques intended for unauthorized access.
- Keep changes focused — one bug fix or feature per pull request.

## Development setup

```bash
git clone https://github.com/Leadrogue/wiflux.git
cd wiflux
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run without installing (from repo root):

```bash
sudo python3 -m wiflux --help
```

## Code style

- Python 3.10+ with type hints where practical
- Match existing module layout: `wiflux/attacks/`, `wiflux/tools/`, etc.
- Use Rich for terminal output; keep MAC addresses safe from emoji/markup parsing (`display.py` helpers)
- Prefer dataclass config over global state

## Submitting changes

1. Fork the repository
2. Create a feature branch: `git checkout -b fix/wps-timeout`
3. Make your changes with clear commit messages
4. Test on a real adapter when touching scan/attack logic
5. Open a pull request describing what changed and why

## Reporting bugs

Include:

- OS and version (e.g., Kali 2026.x)
- `wiflux --help` output or version
- Wireless adapter model
- Full command used
- Expected vs actual behavior
- Relevant log output (redact BSSIDs/ESSIDs if needed)

## Security issues

If you discover a security vulnerability in Wiflux itself (not Wi-Fi attack techniques), please open a private security advisory on GitHub rather than a public issue.