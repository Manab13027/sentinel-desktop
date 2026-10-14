"""OS detection and safe command execution helpers."""
from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys

SYSTEM = platform.system()  # 'Windows', 'Darwin', 'Linux'
IS_WIN = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"

_CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0


def os_key() -> str:
    return "windows" if IS_WIN else "macos" if IS_MAC else "linux"


def is_admin() -> bool:
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def run(cmd: list[str] | str, timeout: int = 30, shell: bool = False) -> tuple[int, str, str]:
    """Run a command, never raising. Returns (code, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            creationflags=_CREATE_NO_WINDOW,
            encoding="utf-8",
            errors="replace",
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def powershell(script: str, timeout: int = 60) -> tuple[int, str, str]:
    return run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )


def run_elevated(commands: list[str], timeout: int = 180) -> tuple[int, str, str]:
    """Run shell commands with admin rights, prompting the user via the OS dialog.

    Windows: PowerShell lines, run through an elevated PowerShell (UAC prompt).
    macOS:   sh lines, run through osascript 'with administrator privileges'.
    Linux:   sh lines through pkexec.
    Only call this with commands produced by the remediation playbooks.
    """
    if is_admin():
        if IS_WIN:
            return powershell("$ErrorActionPreference='Stop'; " + "; ".join(commands), timeout=timeout)
        return run(["/bin/sh", "-c", " && ".join(commands)], timeout=timeout)

    if IS_WIN:
        import base64
        import tempfile
        log = os.path.join(tempfile.gettempdir(), f"sentinel_fix_{os.getpid()}.log")
        body = "; ".join(commands)
        inner = (f"$ErrorActionPreference='Stop'; try {{ & {{ {body} }} *> '{log}'; exit 0 }} "
                 f"catch {{ $_ | Out-File -Append '{log}'; exit 1 }}")
        enc = base64.b64encode(inner.encode("utf-16-le")).decode()
        script = (
            "$p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
            f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc}'; exit $p.ExitCode"
        )
        code, out, err = powershell(script, timeout=timeout)
        try:
            with open(log, encoding="utf-16", errors="replace") as fh:
                out = fh.read()
            os.remove(log)
        except Exception:
            pass
        if "canceled by the user" in err.lower() or "cancelled by the user" in err.lower():
            return 1223, out, "Administrator permission was declined."
        return code, out, err
    if IS_MAC:
        sh = " && ".join(commands).replace("\\", "\\\\").replace('"', '\\"')
        apple = f'do shell script "{sh}" with administrator privileges'
        return run(["osascript", "-e", apple], timeout=timeout)
    return run(["pkexec", "/bin/sh", "-c", " && ".join(commands)], timeout=timeout)


def quote(s: str) -> str:
    return shlex.quote(s)


def host_info() -> dict:
    return {
        "hostname": platform.node(),
        "os": SYSTEM,
        "os_key": os_key(),
        "os_release": platform.release(),
        "os_version": platform.mac_ver()[0] if IS_MAC else platform.version(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
        "admin": is_admin(),
    }
