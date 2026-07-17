# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Import the Visual Studio developer environment into GitHub Actions."""

import os
import subprocess
from pathlib import Path


def command_output(command: list[str] | str) -> str:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> None:
    vswhere = (
        Path(os.environ["ProgramFiles(x86)"])
        / "Microsoft Visual Studio"
        / "Installer"
        / "vswhere.exe"
    )
    installation_path = command_output(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ]
    ).strip()
    if not installation_path:
        raise RuntimeError("Microsoft Visual Studio with C++ tools was not found")

    vsdevcmd = Path(installation_path) / "Common7" / "Tools" / "VsDevCmd.bat"
    if not vsdevcmd.is_file():
        raise FileNotFoundError(vsdevcmd)

    comspec = os.environ["COMSPEC"]
    environment = command_output(
        f'"{comspec}" /d /s /c ""{vsdevcmd}" -arch=x64 -no_logo && set"'
    )
    original_environment = {name.upper(): value for name, value in os.environ.items()}

    github_env = Path(os.environ["GITHUB_ENV"])
    with github_env.open("a", encoding="utf-8", newline="\n") as env_file:
        for line in environment.splitlines():
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            if not name or original_environment.get(name.upper()) == value:
                continue
            print(f"Exporting {name}")
            env_file.write(f"{name}={value}\n")


if __name__ == "__main__":
    main()
