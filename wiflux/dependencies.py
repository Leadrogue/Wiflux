"""Dependency detection and optional apt installation."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from .display import console, print_error, print_info
from .process import which


@dataclass(frozen=True)
class Dependency:
    binary: str
    apt_package: str
    label: str
    required: bool = False


DEPENDENCIES: list[Dependency] = [
    Dependency("airodump-ng", "aircrack-ng", "airodump-ng", required=True),
    Dependency("aireplay-ng", "aircrack-ng", "aireplay-ng", required=True),
    Dependency("airmon-ng", "aircrack-ng", "airmon-ng", required=True),
    Dependency("aircrack-ng", "aircrack-ng", "aircrack-ng", required=True),
    Dependency("iw", "iw", "iw", required=True),
    Dependency("ip", "iproute2", "ip", required=True),
    Dependency("wash", "reaver", "wash (WPS scan)", required=False),
    Dependency("reaver", "reaver", "reaver (WPS)", required=False),
    Dependency("bully", "bully", "bully (WPS)", required=False),
    Dependency("hcxdumptool", "hcxdumptool", "hcxdumptool (PMKID)", required=False),
    Dependency("hcxpcapngtool", "hcxtools", "hcxpcapngtool", required=False),
    Dependency("hashcat", "hashcat", "hashcat (crack)", required=False),
    Dependency("packetforge-ng", "aircrack-ng", "packetforge-ng (WEP)", required=False),
    Dependency("pixiewps", "pixiewps", "pixiewps (offline WPS)", required=False),
    Dependency("tshark", "tshark", "tshark (WPS cap parse)", required=False),
]


def missing_dependencies() -> list[Dependency]:
    return [dep for dep in DEPENDENCIES if not which(dep.binary)]


def missing_required() -> list[Dependency]:
    return [dep for dep in missing_dependencies() if dep.required]


def packages_for(deps: list[Dependency]) -> list[str]:
    return sorted({dep.apt_package for dep in deps})


def _read_tty_line(prompt: str) -> str:
    if os.path.exists("/dev/tty"):
        fd = os.open("/dev/tty", os.O_RDWR)
        try:
            os.write(fd, prompt.encode())
            data = b""
            while True:
                chunk = os.read(fd, 1)
                if not chunk or chunk in (b"\n", b"\r"):
                    break
                data += chunk
            return data.decode(errors="replace").strip().lower()
        finally:
            os.close(fd)
    return input(prompt).strip().lower()


def prompt_install_missing(deps: list[Dependency]) -> bool:
    if not deps:
        return False

    console.print()
    console.print("[bold cyan]Dependency Check[/]")
    console.print("[dim]The following tools are not installed:[/]")
    for dep in deps:
        tag = "[red]required[/]" if dep.required else "[yellow]optional[/]"
        console.print(
            f"  [cyan]•[/] {dep.label} [dim]({dep.binary})[/] — apt: [green]{dep.apt_package}[/] {tag}"
        )
    console.print()
    console.print("[dim]Install missing packages via apt?[/] [bold yellow][Y/n][/]")
    answer = _read_tty_line("> ")
    return answer in ("", "y", "yes")


def install_packages(packages: list[str]) -> bool:
    if not packages:
        return True
    if not shutil.which("apt-get"):
        print_error("apt-get not found — install packages manually.")
        return False

    cmd = ["apt-get", "install", "-y", *packages]
    print_info(f"Running: [cyan]{' '.join(cmd)}[/]")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except OSError as exc:
        print_error(f"Install failed: {exc}")
        return False


def restart_program() -> None:
    print_info("[green]Restarting Wiflux…[/]")
    os.execv(sys.executable, [sys.executable, "-m", "wiflux", *sys.argv[1:]])


def run_startup_dependency_check() -> None:
    """After splash: offer to install missing deps and restart."""
    missing = missing_dependencies()
    if not missing:
        return

    if not prompt_install_missing(missing):
        req = missing_required()
        if req:
            print_error(
                f"Missing required tools: {', '.join(d.binary for d in req)}"
            )
            sys.exit(1)
        print_info("[yellow]Continuing without optional tools.[/]")
        return

    pkgs = packages_for(missing)
    if install_packages(pkgs):
        restart_program()
    print_error("Package install failed — fix manually and re-run.")
    sys.exit(1)