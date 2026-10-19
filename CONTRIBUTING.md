# Contributing

Thank you! The most valuable contributions are **checks that catch real misconfigurations** and **fixes that cannot lock anyone out**. Issues are welcome in English or Japanese. In a PR, write the skill's files (checks, fixes, scripts) in English, since Claude reads them; the PR description can be in either language.

The easiest way to contribute is an issue written by Claude: after an audit, the skill has Claude offer to report anything the skill got wrong or missed ([feedback.md](skills/network-security-audit/feedback.md)). Issues are preferred over pull requests — the maintainer folds them into the skill, so many reports never conflict with each other. Pull requests are still welcome for larger additions (a new OS, a new helper); please open an issue first.

The skill runs every command through [PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP), so please test your change the same way: Claude Code driving the target's PowerShell 7 console (remote control for another machine).

## Adding a check

Put it in the file for its OS under `skills/network-security-audit/checks/`. Each check needs:

- **The command**, read-only. Mark it `sudo` / `Admin` if it needs elevation. Native commands are fine — they run as they are in PowerShell 7.
- **What a finding looks like** — the value or line that means "fix this", and what is normal.
- **Where you tested it** — OS and version (e.g. Ubuntu 24.04, Windows Server 2022) and the PowerShell.MCP version.
- **Why it matters**, with a reference if there is one (CIS Benchmark, vendor documentation, an advisory).

Real stories are especially welcome: "this setting was overridden by X and only `Y` showed it".

## Adding or changing a helper function

The helper functions live in the PowerShell module `module/NetworkSecurityAudit/` (published to the PowerShell Gallery), with Pester tests in `module/tests/`. They encode rules that are easy to get wrong by hand. Keep them:

- **Read-only.** A helper never changes the target.
- **Exported and documented**: listed in `FunctionsToExport` of the manifest, with comment-based help that says what it returns and which rule it applies. OS-specific functions start with `Assert-Platform`.
- **Returning objects**, not formatted text.
- **Tested on the OS it targets**, through a PowerShell.MCP remote console, with the version noted in the PR.

Run the tests with `Invoke-Pester module/tests`, on each OS the change touches. CI runs them on Windows and Linux for every push and PR that touches `module/`. 

## Releases

The skill and the module share one version number and are released together. Pushes to `main` do not reach users: the marketplace serves the plugin from the `release` branch. To release X.Y.Z, a maintainer sets `version` in `.claude-plugin/plugin.json` and `ModuleVersion` and `ReleaseNotes` in the module manifest to X.Y.Z, and pushes a tag `vX.Y.Z` on that commit of `main`. The release workflow tests, publishes the module to the PowerShell Gallery, moves `release` to the tag and creates a GitHub Release — so the module bundled in a released plugin is always the one on the Gallery with the same version. Step by step, with what to do when a step fails: [RELEASING.md](RELEASING.md).

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
