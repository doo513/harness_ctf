from __future__ import annotations

import argparse
import cmd
import json
import shlex
import sys
from pathlib import Path

from ctf_harness.configuration import ConfigurationError
from ctf_harness.operator import OperatorError, OperatorService


def _render(value) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


class OperatorShell(cmd.Cmd):
    intro = "Verified CTF Harness operator shell. Type help or ? to list commands."
    prompt = "harness> "

    def __init__(self, service: OperatorService):
        super().__init__()
        self.service = service

    def _run(self, fn) -> None:
        try:
            value = fn()
            if value is not None:
                _render(value)
        except (OperatorError, ConfigurationError, ValueError, RuntimeError) as exc:
            print(f"error: {exc}")

    def do_status(self, arg: str) -> None:
        """status: show secret-free configuration and readiness state."""
        self._run(self.service.status)

    def do_doctor(self, arg: str) -> None:
        """doctor: run read-only operational diagnostics."""
        self._run(lambda: self.service.doctor.run().descriptor())

    def do_challenges(self, arg: str) -> None:
        """challenges: list challenges from the active competition site."""
        self._run(self.service.challenges)

    def do_challenge(self, arg: str) -> None:
        """challenge ID: show one challenge snapshot."""
        challenge_id = arg.strip()
        if not challenge_id:
            print("usage: challenge ID")
            return
        self._run(lambda: self.service.challenge(challenge_id))

    def do_download(self, arg: str) -> None:
        """download ID WORKSPACE: download challenge artifacts without admission."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            print(f"error: {exc}")
            return
        if len(parts) != 2:
            print("usage: download ID WORKSPACE")
            return
        self._run(lambda: self.service.download_challenge(parts[0], parts[1]))

    def do_mcp(self, arg: str) -> None:
        """mcp: show configured MCP servers and policy."""
        self._run(self.service.mcp_servers)

    def do_mcp_tools(self, arg: str) -> None:
        """mcp_tools SERVER: list allowlisted MCP tools."""
        server = arg.strip()
        if not server:
            print("usage: mcp_tools SERVER")
            return
        self._run(lambda: self.service.mcp_tools(server))

    def do_mcp_call(self, arg: str) -> None:
        """mcp_call SERVER TOOL JSON: explicitly invoke an allowlisted MCP tool."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            print(f"error: {exc}")
            return
        if len(parts) != 3:
            print("usage: mcp_call SERVER TOOL JSON")
            return
        try:
            arguments = json.loads(parts[2])
        except json.JSONDecodeError as exc:
            print(f"error: arguments must be JSON: {exc}")
            return
        if not isinstance(arguments, dict):
            print("error: arguments JSON must be an object")
            return
        self._run(lambda: self.service.mcp_call(parts[0], parts[1], arguments))

    def do_submit(self, arg: str) -> None:
        """submit ID FLAG: explicitly submit a candidate when site allow_submit=true."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            print(f"error: {exc}")
            return
        if len(parts) != 2:
            print("usage: submit ID FLAG")
            return
        self._run(lambda: {"accepted": self.service.submit_flag(parts[0], parts[1])})

    def do_exit(self, arg: str) -> bool:
        """exit: leave the operator shell."""
        return True

    def do_quit(self, arg: str) -> bool:
        """quit: leave the operator shell."""
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verified CTF Harness operator interface")
    parser.add_argument("--config", default="harness.toml", help="path to harness TOML configuration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("doctor")
    sub.add_parser("challenges")
    challenge = sub.add_parser("challenge")
    challenge.add_argument("challenge_id")
    download = sub.add_parser("download")
    download.add_argument("challenge_id")
    download.add_argument("workspace", type=Path)
    sub.add_parser("mcp")
    mcp_tools = sub.add_parser("mcp-tools")
    mcp_tools.add_argument("server")
    mcp_call = sub.add_parser("mcp-call")
    mcp_call.add_argument("server")
    mcp_call.add_argument("tool")
    mcp_call.add_argument("arguments", help="JSON object")
    submit = sub.add_parser("submit")
    submit.add_argument("challenge_id")
    submit.add_argument("candidate")
    sub.add_parser("shell")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        service = OperatorService.from_path(args.config)
        if args.command == "status":
            _render(service.status())
        elif args.command == "doctor":
            report = service.doctor.run()
            _render(report.descriptor())
            return 0 if report.ready else 2
        elif args.command == "challenges":
            _render(service.challenges())
        elif args.command == "challenge":
            _render(service.challenge(args.challenge_id))
        elif args.command == "download":
            _render(service.download_challenge(args.challenge_id, args.workspace))
        elif args.command == "mcp":
            _render(service.mcp_servers())
        elif args.command == "mcp-tools":
            _render(service.mcp_tools(args.server))
        elif args.command == "mcp-call":
            arguments = json.loads(args.arguments)
            if not isinstance(arguments, dict):
                raise ValueError("MCP arguments must be a JSON object")
            _render(service.mcp_call(args.server, args.tool, arguments))
        elif args.command == "submit":
            _render({"accepted": service.submit_flag(args.challenge_id, args.candidate)})
        elif args.command == "shell":
            OperatorShell(service).cmdloop()
        return 0
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON arguments: {exc}", file=sys.stderr)
    except (ConfigurationError, OperatorError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
