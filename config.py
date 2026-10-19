"""Load KEY=VALUE lines from a .env file next to the scripts. No dependency.

Imported first by every module, before any os.environ read. Variables already
set in the real environment (crontab, shell) win over the file.
Set VULNSG_ENV_FILE to use another file (the tests point it to /dev/null).
"""
import os
from pathlib import Path

ENV_FILE = Path(os.environ.get("VULNSG_ENV_FILE", Path(__file__).resolve().parent / ".env"))


def load_env(path=ENV_FILE):
    try:
        lines = Path(path).read_text().splitlines()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


load_env()
