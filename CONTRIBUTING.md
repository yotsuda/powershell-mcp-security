# Contributing

Thank you! The most valuable contributions are **checks that catch real misconfigurations** and **fixes that cannot lock anyone out**. Issues and PRs in English or Japanese are welcome.

The skill runs every command through [PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP), so please test your change the same way: Claude Code driving the target's PowerShell 7 console (remote control for another machine).

## Adding a check

Put it in the file for its OS under `skills/network-security-audit/checks/`. Each check needs:

- **The command**, read-only. Mark it `sudo` / `Admin` if it needs elevation. Native commands are fine — they run as they are in PowerShell 7.
- **What a finding looks like** — the value or line that means "fix this", and what is normal.
- **Where you tested it** — OS and version (e.g. Ubuntu 24.04, Windows Server 2022) and the PowerShell.MCP version.
- **Why it matters**, with a reference if there is one (CIS Benchmark, vendor documentation, an advisory).

Real stories are especially welcome: "this setting was overridden by X and only `Y` showed it".

## Adding or changing a helper function

Helpers in `skills/network-security-audit/scripts/` encode rules that are easy to get wrong by hand. Keep them:

- **Read-only.** A helper never changes the target.
- **Self-contained and global** (`function global:Verb-Noun`), with comment-based help that says what it returns and which rule it applies.
- **Returning objects**, not formatted text.
- **Tested on the OS it targets**, through a PowerShell.MCP remote console, with the version noted in the PR.

They are written so they can later move into a PowerShell module on the Gallery without changing their interface.

## Adding or changing a fix

Fixes change systems, so the bar is higher. Include:

- The **order** of steps and why it is lockout-safe.
- How to **validate** before applying (e.g. `sshd -t`, `visudo -c`).
- How to **verify** it worked, from inside and outside.
- How to **undo** it.

## Not accepted

- Offensive techniques, exploits, or scanning beyond the target the user names.
- Commands that send data from the target anywhere other than the user's AI session.
- Anything that asks the user to paste passwords or secrets into the chat.

## Testing your change locally

```
claude --plugin-dir ./powershell-mcp-security
```

starts Claude Code with your working copy loaded as the plugin.

## Keep SKILL.md small

`SKILL.md` is loaded whenever the skill is used; details belong in the files it links to.
