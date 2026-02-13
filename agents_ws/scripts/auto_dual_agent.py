#!/usr/bin/env python3
"""
Automate an N-agent workflow loop using `codex exec`.

Core behavior:
- Configure agent list and role split at startup.
- First lead agent publishes plan/responsibilities.
- Agents collaborate through AGENT_SYNC.md using FEED_TO/FEED_PROMPT tags.
- Stop only when all agents set READY_TO_END=YES in the same round.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROUND_RE = re.compile(r"\[R(\d+)\]")
READY_RE = re.compile(r"^\[([A-Za-z0-9_-]+)\]\[R(\d+)\]\[READY_TO_END\]=(YES|NO)\s*$", re.MULTILINE)
FEED_TO_LINE_RE = re.compile(r"^\[([A-Za-z0-9_-]+)\]\[R(\d+)\]\[FEED_TO\]=(.*)$")
FEED_PROMPT_LINE_RE = re.compile(r"^\[([A-Za-z0-9_-]+)\]\[R(\d+)\]\[FEED_PROMPT\]=(.*)$")
AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PERMISSION_POLICIES = {"read-only", "workspace-write", "danger-full-access", "bypass"}


@dataclass
class FeedEvent:
    event_id: str
    sender: str
    round_no: int
    targets: list[str]
    prompt: str
    line_no: int


def now_iso() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat()


def display_path(path: Path, workspace: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(path)


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def append_lines(path: Path, lines: list[str]) -> None:
    with path.open("a", encoding="utf-8") as f:
        if path.stat().st_size > 0 and not load_text(path).endswith("\n"):
            f.write("\n")
        for line in lines:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")


def detect_active_round(sync_text: str) -> int:
    rounds = [int(m.group(1)) for m in ROUND_RE.finditer(sync_text)]
    if not rounds:
        return 1
    max_round = max(rounds)
    if f"[TASK][R{max_round}][CLOSED]=YES" in sync_text:
        return max_round + 1
    return max_round


def parse_agents(value: str) -> list[str]:
    agents: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        name = raw.strip()
        if not name:
            continue
        if not AGENT_NAME_RE.match(name):
            raise ValueError(f"Invalid agent name: {name!r}. Use [A-Za-z0-9_-].")
        if name in seen:
            continue
        seen.add(name)
        agents.append(name)
    if len(agents) < 2:
        raise ValueError("At least 2 agents are required.")
    return agents


def parse_agent_roles(agents: list[str], role_items: list[str], role_file: Path | None) -> dict[str, str]:
    roles: dict[str, str] = {a: "" for a in agents}

    if role_file:
        if not role_file.exists():
            raise ValueError(f"Role file not found: {role_file}")
        try:
            data = json.loads(role_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Role file is not valid JSON: {role_file}") from exc
        if not isinstance(data, dict):
            raise ValueError("Role file must be a JSON object: {\"AGENT\": \"role desc\", ...}")
        for k, v in data.items():
            if k in roles and isinstance(v, str):
                roles[k] = v.strip()

    for item in role_items:
        if "=" not in item:
            raise ValueError(f"Invalid --agent-role value: {item!r}. Expected AGENT=ROLE_TEXT")
        agent, desc = item.split("=", 1)
        agent = agent.strip()
        desc = desc.strip()
        if agent not in roles:
            raise ValueError(f"--agent-role references unknown agent: {agent}")
        roles[agent] = desc

    for agent in agents:
        if not roles[agent]:
            roles[agent] = f"General contributor for {agent}."
    return roles


def parse_agent_permissions(
    agents: list[str],
    permission_items: list[str],
    default_policy: str,
) -> dict[str, str]:
    if default_policy not in PERMISSION_POLICIES:
        raise ValueError(
            f"Invalid default permission policy: {default_policy}. "
            f"Expected one of: {sorted(PERMISSION_POLICIES)}"
        )

    policies: dict[str, str] = {agent: default_policy for agent in agents}
    for item in permission_items:
        if "=" not in item:
            raise ValueError(
                f"Invalid --agent-permission value: {item!r}. "
                "Expected AGENT=read-only|workspace-write|danger-full-access|bypass"
            )
        agent, policy = item.split("=", 1)
        agent = agent.strip()
        policy = policy.strip()
        if agent not in policies:
            raise ValueError(f"--agent-permission references unknown agent: {agent}")
        if policy not in PERMISSION_POLICIES:
            raise ValueError(
                f"Invalid policy for {agent}: {policy}. "
                f"Expected one of: {sorted(PERMISSION_POLICIES)}"
            )
        policies[agent] = policy
    return policies


def ensure_sync_file(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Agent Sync Log",
                "",
                "## Shared Rules",
                "- Append only. Never rewrite history.",
                "- Configure agent list and role split at startup.",
                "- Any FEED_TO must target 1..(n-1) valid agents.",
                "- Stop condition: all agents set READY_TO_END=YES in the same round.",
                "",
                "## Task",
                "- Filled by orchestration script per round.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def ensure_round_stub(
    sync_file: Path,
    round_no: int,
    task_text: str,
    agents: list[str],
    lead: str,
    role_map: dict[str, str],
) -> None:
    text = load_text(sync_file)
    if f"## R{round_no}" in text:
        return

    lines = [
        "",
        f"## R{round_no}",
        f"[TASK][R{round_no}][STARTED_AT]={now_iso()}",
        f"[TASK][R{round_no}][DESCRIPTION]={task_text.strip()}",
        f"[TASK][R{round_no}][AGENTS]={','.join(agents)}",
        f"[TASK][R{round_no}][LEAD]={lead}",
    ]
    for agent in agents:
        lines.append(f"[TASK][R{round_no}][ROLE::{agent}]={role_map[agent]}")
    for agent in agents:
        lines.append(f"[{agent}][R{round_no}][READY_TO_END]=NO")
    lines.append("")
    append_lines(sync_file, lines)


def round_is_closed(sync_text: str, round_no: int) -> bool:
    return f"[TASK][R{round_no}][CLOSED]=YES" in sync_text


def ready_state(sync_text: str, round_no: int, agents: list[str]) -> dict[str, bool]:
    state = {a: False for a in agents}
    for agent, rd, flag in READY_RE.findall(sync_text):
        if int(rd) == round_no and agent in state:
            state[agent] = flag == "YES"
    return state


def parse_targets(raw: str, agents: list[str], sender: str) -> list[str]:
    text = raw.strip()
    if not text or text.upper() == "NONE":
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in text.split(","):
        tgt = item.strip()
        if not tgt or tgt == sender:
            continue
        if tgt not in agents:
            continue
        if tgt in seen:
            continue
        seen.add(tgt)
        out.append(tgt)
    return out


def parse_feed_events(sync_text: str, round_no: int, agents: list[str]) -> list[FeedEvent]:
    events: list[FeedEvent] = []
    lines = sync_text.splitlines()

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        m_to = FEED_TO_LINE_RE.match(line)
        if m_to:
            sender, rd, targets_raw = m_to.groups()
            if int(rd) != round_no or sender not in agents:
                continue
            targets = parse_targets(targets_raw, agents, sender)
            events.append(
                FeedEvent(
                    event_id=f"{round_no}:{sender}:{idx}",
                    sender=sender,
                    round_no=round_no,
                    targets=targets,
                    prompt="",
                    line_no=idx,
                )
            )
            continue

        m_prompt = FEED_PROMPT_LINE_RE.match(line)
        if not m_prompt:
            continue
        sender, rd, prompt_raw = m_prompt.groups()
        if int(rd) != round_no or sender not in agents:
            continue
        prompt = prompt_raw.strip()
        for event in reversed(events):
            if event.sender == sender and event.round_no == round_no and not event.prompt:
                event.prompt = prompt
                break

    filtered: list[FeedEvent] = []
    for event in events:
        if not event.targets:
            continue
        if not event.prompt or event.prompt.upper() == "NONE":
            continue
        filtered.append(event)
    return filtered


def collect_inbound_for_role(
    role: str,
    events: list[FeedEvent],
    delivered_pairs: set[str],
) -> list[FeedEvent]:
    inbound: list[FeedEvent] = []
    for event in sorted(events, key=lambda x: x.line_no):
        if role not in event.targets:
            continue
        pair_id = f"{event.event_id}->{role}"
        if pair_id in delivered_pairs:
            continue
        inbound.append(event)
        delivered_pairs.add(pair_id)
    return inbound


def pick_feed_target(
    events: list[FeedEvent],
    agents: list[str],
    delivered_pairs: set[str],
) -> str | None:
    for event in sorted(events, key=lambda x: x.line_no):
        for target in event.targets:
            if target not in agents:
                continue
            pair_id = f"{event.event_id}->{target}"
            if pair_id not in delivered_pairs:
                return target
    return None


def resolve_codex_bin(cli_value: str | None) -> str | None:
    if cli_value:
        candidate = Path(cli_value).expanduser()
        if candidate.is_file():
            return str(candidate)
        resolved = shutil.which(cli_value)
        if resolved:
            return resolved
        return None

    env_value = os.environ.get("CODEX_BIN", "").strip()
    if env_value:
        candidate = Path(env_value).expanduser()
        if candidate.is_file():
            return str(candidate)
        resolved = shutil.which(env_value)
        if resolved:
            return resolved

    resolved = shutil.which("codex")
    if resolved:
        return resolved

    all_candidates = list(Path.home().glob(".vscode/extensions/openai.chatgpt-*/bin/linux-*/codex"))
    if not all_candidates:
        return None

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        preferred = [p for p in all_candidates if "/linux-x86_64/" in p.as_posix()]
    elif machine in ("aarch64", "arm64"):
        preferred = [p for p in all_candidates if "/linux-aarch64/" in p.as_posix()]
    else:
        preferred = []

    pool = preferred if preferred else all_candidates
    return str(sorted(pool, key=lambda p: p.as_posix())[-1])


def build_prompt(
    role: str,
    role_desc: str,
    role_permission: str,
    lead: str,
    agents: list[str],
    task_text: str,
    round_no: int,
    turn_idx: int,
    sync_file_display: str,
    inbound: list[FeedEvent],
    kickoff_turn: bool,
    extra_docs_display: list[str],
) -> str:
    all_agents = ", ".join(agents)
    others = [a for a in agents if a != role]
    others_csv = ", ".join(others) if others else "(none)"
    inbound_lines = []
    if inbound:
        for i, event in enumerate(inbound, start=1):
            inbound_lines.append(f"{i}. from={event.sender}, targets={','.join(event.targets)}, prompt={event.prompt}")
    else:
        inbound_lines.append("(none)")

    extra_doc_text = ""
    if extra_docs_display:
        extra_doc_text = "Additional shared docs: " + ", ".join(extra_docs_display) + "\n"

    kickoff_text = ""
    if kickoff_turn:
        kickoff_text = (
            "This is kickoff turn for the lead coordinator.\\n"
            "Before implementation, publish an explicit collaboration outline for ALL agents.\\n"
            "The outline must include: each agent's responsibility, dependencies, and first action.\\n"
            f"At kickoff, send at least one FEED_TO to agents other than {lead}.\\n"
        )

    return (
        f"You are agent {role}.\\n"
        f"Role split for {role}: {role_desc}\\n"
        f"Permission scope for {role}: {role_permission}\\n"
        f"Task: {task_text.strip()}\\n"
        f"Round: R{round_no}, turn: {turn_idx}\\n"
        f"Lead agent: {lead}\\n"
        f"Agent roster: {all_agents}\\n"
        f"Shared sync doc: {sync_file_display}\\n"
        f"{extra_doc_text}"
        f"Allowed FEED_TO targets for you: {others_csv}\\n\\n"
        f"{kickoff_text}"
        "Inbound prompts for this turn:\\n"
        + "\\n".join(inbound_lines)
        + "\\n\\n"
        "Execution rules:\\n"
        "1) Read repository and sync doc first.\\n"
        "2) Perform one concrete step in your role.\\n"
        "3) Append EXACTLY one turn block to sync doc using this template:\\n"
        f"[{role}][R{round_no}][<ISO8601 timestamp>]\\n"
        f"- Role: {role_desc}\\n"
        "- Summary:\\n"
        "- Files:\\n"
        "- Commands:\\n"
        "- Results:\\n"
        "- Next:\\n"
        f"[{role}][R{round_no}][FEED_TO]=AGENT_A,AGENT_B or NONE\\n"
        f"[{role}][R{round_no}][FEED_PROMPT]=single-line instruction for FEED_TO or NONE\\n"
        f"[{role}][R{round_no}][READY_TO_END]=YES|NO\\n\\n"
        "Constraints:\\n"
        "- FEED_TO must be NONE or a subset of listed agent roster, excluding yourself.\\n"
        "- If FEED_TO is not NONE, FEED_PROMPT must be concrete and actionable.\\n"
        "- Set READY_TO_END=YES only when your role has no remaining tasks for this round.\\n"
        "- Stop after this one turn.\\n"
    )


def run_codex_turn(
    codex_bin: str,
    workspace: Path,
    prompt: str,
    output_file: Path,
    model: str | None,
    reasoning_effort: str | None,
    sandbox: str,
    dangerous: bool,
    timeout_sec: int,
) -> tuple[int, str]:
    cmd = [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "-C",
        str(workspace),
        "--color",
        "never",
        "--output-last-message",
        str(output_file),
    ]
    if model:
        cmd.extend(["-m", model])
    if reasoning_effort:
        cmd.extend(["-c", f'model_reasoning_effort="{reasoning_effort}"'])

    if dangerous:
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
    else:
        cmd.extend(["--sandbox", sandbox, "-c", 'approval_policy="never"'])

    cmd.append("-")

    proc = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout_sec,
    )
    tail = proc.stdout[-6000:] if proc.stdout else ""
    if proc.stderr:
        tail += "\n" + proc.stderr[-2000:]
    return proc.returncode, tail


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automate N-agent collaboration turns with codex exec.")
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Workspace root.")
    parser.add_argument("--sync-file", type=Path, default=Path("AGENT_SYNC.md"), help="Main shared sync file.")
    parser.add_argument("--extra-doc", action="append", default=[], help="Additional shared docs (repeatable).")
    parser.add_argument("--codex-bin", type=str, default="", help="Path or command name for codex executable.")

    parser.add_argument("--task", type=str, default="", help="Task description.")
    parser.add_argument("--task-file", type=Path, default=None, help="Read task description from file.")

    parser.add_argument("--agents", type=str, default="DEV,QA", help="Comma-separated agent names.")
    parser.add_argument("--lead", type=str, default="", help="Lead agent name. Defaults to first in --agents.")
    parser.add_argument(
        "--agent-role",
        action="append",
        default=[],
        help="Per-agent role split, format AGENT=ROLE_TEXT (repeatable).",
    )
    parser.add_argument(
        "--agent-permission",
        action="append",
        default=[],
        help=(
            "Per-agent permission policy, format "
            "AGENT=read-only|workspace-write|danger-full-access|bypass"
        ),
    )
    parser.add_argument(
        "--agent-roles-file",
        type=Path,
        default=None,
        help="JSON file mapping agents to role text.",
    )
    parser.add_argument(
        "--allow-lead-turns",
        action="store_true",
        help="Allow lead agent to participate in regular round-robin after kickoff.",
    )

    parser.add_argument("--round", type=int, default=None, help="Round number. Auto-detected if omitted.")
    parser.add_argument("--max-turns", type=int, default=20, help="Maximum loop turns.")
    parser.add_argument("--sleep-seconds", type=float, default=1.0, help="Pause between turns.")
    parser.add_argument("--model", type=str, default=None, help="Codex model override.")
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default=None,
        help="Model reasoning effort override.",
    )
    parser.add_argument(
        "--sandbox",
        choices=["read-only", "workspace-write", "danger-full-access"],
        default="workspace-write",
        help="Sandbox mode for codex exec (used when --dangerous is not set).",
    )
    parser.add_argument(
        "--dangerous",
        action="store_true",
        help="Use --dangerously-bypass-approvals-and-sandbox for unattended runs.",
    )
    parser.add_argument("--timeout-sec", type=int, default=1800, help="Per-turn timeout in seconds.")
    parser.add_argument("--log-dir", type=Path, default=Path(".agent_runs"), help="Store turn outputs here.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    codex_bin = resolve_codex_bin(args.codex_bin if args.codex_bin else None)
    if codex_bin is None:
        print("ERROR: `codex` command not found in PATH.", file=sys.stderr)
        print(
            "Hint: set CODEX_BIN or pass --codex-bin, e.g. "
            "--codex-bin ~/.vscode/extensions/openai.chatgpt-*/bin/linux-x86_64/codex",
            file=sys.stderr,
        )
        return 2

    try:
        agents = parse_agents(args.agents)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    lead = args.lead.strip() if args.lead else agents[0]
    if lead not in agents:
        print(f"ERROR: lead agent {lead!r} is not in --agents list.", file=sys.stderr)
        return 2

    try:
        role_map = parse_agent_roles(agents, args.agent_role, args.agent_roles_file)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    default_policy = "bypass" if args.dangerous else args.sandbox
    try:
        permission_map = parse_agent_permissions(agents, args.agent_permission, default_policy)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    workspace = args.workspace.resolve()
    sync_file = (workspace / args.sync_file).resolve() if not args.sync_file.is_absolute() else args.sync_file
    log_dir = (workspace / args.log_dir).resolve() if not args.log_dir.is_absolute() else args.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)

    extra_docs: list[Path] = []
    for raw in args.extra_doc:
        p = Path(raw)
        extra_docs.append((workspace / p).resolve() if not p.is_absolute() else p)
    extra_docs_display = [display_path(p, workspace) for p in extra_docs]
    sync_file_display = display_path(sync_file, workspace)

    task_text = args.task.strip()
    if args.task_file:
        if not args.task_file.exists():
            print(f"ERROR: task file not found: {args.task_file}", file=sys.stderr)
            return 2
        task_text = args.task_file.read_text(encoding="utf-8").strip()
    if not task_text:
        print("ERROR: provide --task or --task-file.", file=sys.stderr)
        return 2

    ensure_sync_file(sync_file)
    sync_text = load_text(sync_file)
    round_no = args.round or detect_active_round(sync_text)
    ensure_round_stub(sync_file, round_no, task_text, agents, lead, role_map)
    sync_text = load_text(sync_file)

    if round_is_closed(sync_text, round_no):
        print(f"Round R{round_no} already closed. Nothing to do.")
        return 0

    delivered_pairs: set[str] = set()
    kickoff_done = False
    cycle_agents = agents[:] if args.allow_lead_turns else [a for a in agents if a != lead]
    if not cycle_agents:
        cycle_agents = agents[:]
    cycle_idx = 0

    print(
        f"Start n-agent loop: round=R{round_no}, agents={agents}, lead={lead}, max_turns={args.max_turns}"
    )
    print(f"Sync file: {sync_file_display}")
    print(f"Using codex binary: {codex_bin}")
    if args.model:
        print(f"Model override: {args.model}")
    if args.reasoning_effort:
        print(f"Reasoning effort override: {args.reasoning_effort}")
    print(f"Agent permissions: {permission_map}")

    for turn_idx in range(1, args.max_turns + 1):
        sync_text = load_text(sync_file)
        state = ready_state(sync_text, round_no, agents)
        if all(state.values()):
            if not round_is_closed(sync_text, round_no):
                append_lines(
                    sync_file,
                    [
                        f"[TASK][R{round_no}][DONE]=YES",
                        f"[TASK][R{round_no}][DONE_AT]={now_iso()}",
                        f"[TASK][R{round_no}][CLOSED]=YES",
                        f"[TASK][R{round_no}][CLOSED_AT]={now_iso()}",
                    ],
                )
            print(f"Round R{round_no} closed (all agents READY_TO_END=YES).")
            return 0

        events = parse_feed_events(sync_text, round_no, agents)

        if not kickoff_done:
            role = lead
        else:
            feed_target = pick_feed_target(events, agents, delivered_pairs)
            if feed_target:
                role = feed_target
            else:
                role = cycle_agents[cycle_idx]
                cycle_idx = (cycle_idx + 1) % len(cycle_agents)

        inbound = collect_inbound_for_role(role, events, delivered_pairs)
        kickoff_turn = role == lead and not kickoff_done

        prompt = build_prompt(
            role=role,
            role_desc=role_map[role],
            role_permission=permission_map[role],
            lead=lead,
            agents=agents,
            task_text=task_text,
            round_no=round_no,
            turn_idx=turn_idx,
            sync_file_display=sync_file_display,
            inbound=inbound,
            kickoff_turn=kickoff_turn,
            extra_docs_display=extra_docs_display,
        )

        out_file = log_dir / f"R{round_no}_T{turn_idx}_{role}.last_message.txt"
        role_policy = permission_map[role]
        role_dangerous = role_policy == "bypass"
        role_sandbox = "workspace-write" if role_dangerous else role_policy
        rc, tail = run_codex_turn(
            codex_bin=codex_bin,
            workspace=workspace,
            prompt=prompt,
            output_file=out_file,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            sandbox=role_sandbox,
            dangerous=role_dangerous,
            timeout_sec=args.timeout_sec,
        )
        print(
            f"[turn {turn_idx}] role={role} policy={role_policy} rc={rc} "
            f"output={display_path(out_file, workspace)}"
        )

        if rc != 0:
            print("Codex turn failed, tail output:")
            print(tail)
            append_lines(
                sync_file,
                [
                    f"[TASK][R{round_no}][ERROR_AT]={now_iso()}",
                    f"[TASK][R{round_no}][ERROR_ROLE]={role}",
                    f"[TASK][R{round_no}][ERROR_RC]={rc}",
                ],
            )
            return rc

        if kickoff_turn:
            kickoff_done = True

        sync_text = load_text(sync_file)
        state = ready_state(sync_text, round_no, agents)
        state_str = ", ".join(f"{k}={'YES' if v else 'NO'}" for k, v in state.items())
        print(f"[turn {turn_idx}] READY state: {state_str}")

        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)

    append_lines(
        sync_file,
        [
            f"[TASK][R{round_no}][AUTO_STOP]=MAX_TURNS",
            f"[TASK][R{round_no}][AUTO_STOP_AT]={now_iso()}",
        ],
    )
    print(f"Stopped after max turns ({args.max_turns}) without full completion.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
