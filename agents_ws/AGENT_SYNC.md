# Agent Sync Log

## Shared Rules
- Append only. Never rewrite history.
- Configure agent list and role split at startup.
- Any `FEED_TO` must target 1..(n-1) valid agents.
- Stop condition: all agents set `READY_TO_END=YES` in the same round.

## Task
- Filled by orchestration script per round.

## Round Format (reference)
[AGENT_X][Rk][<ISO8601 timestamp>]
- Role:
- Summary:
- Files:
- Commands:
- Results:
- Next:
[AGENT_X][Rk][FEED_TO]=AGENT_Y,AGENT_Z or NONE
[AGENT_X][Rk][FEED_PROMPT]=single-line prompt or NONE
[AGENT_X][Rk][READY_TO_END]=YES|NO
