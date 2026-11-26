# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
from __future__ import annotations

import re
from pathlib import Path

from strix.interface.cli_name import CLI_NAME


_PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "strix"
_UPSTREAM_COMMAND = re.compile(
    r"\bstrix (cloud|auth|view|completions|--resume|--target|--update)\b"
)


def test_cli_name_is_recon() -> None:
    assert CLI_NAME == "recon"


def test_no_user_facing_text_tells_users_to_run_strix() -> None:
    offenders = [
        f"{path.relative_to(_PACKAGE_ROOT.parent)}:{number}"
        for path in sorted(_PACKAGE_ROOT.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _UPSTREAM_COMMAND.search(line)
    ]
    assert offenders == []


def test_installer_script_is_gone() -> None:
    assert not (_PACKAGE_ROOT.parent / "scripts" / "install.sh").exists()
