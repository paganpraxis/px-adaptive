import argparse
import json
from pathlib import Path

from .smoke import run_smoke


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="pxadaptive")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("smoke", "run"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True, type=Path)
        command.add_argument("--output", required=True, type=Path)
        if name == "run":
            command.add_argument("--data", required=True, type=Path)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    config = json.loads(args.config.read_text())
    if args.command == "smoke":
        manifest = run_smoke(config, args.output)
        return 0 if manifest["status"] == "passed" else 1
    from .experiment import run_experiment

    run_experiment(config, args.data, args.output)
    return 0
