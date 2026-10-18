# Privacy

powershell-mcp-security is a set of instructions and helper scripts for Claude. It has no server, collects nothing, and sends nothing to its author or to anyone else.

## What it reads

During an audit, Claude runs read-only commands on the machine you ask it to audit, through a PowerShell.MCP console that shows every command. Some of what those commands return can identify people:

- local account names and the members of administrator groups;
- user names and source IP addresses in login logs (SSH, Windows Security log);
- the comments of SSH authorized keys, which often hold `user@host` or an email address. The keys are public keys; only their fingerprints are listed, never their text.

These are read only to check who can log in and from where.

## Where it goes

Command output goes to your own Claude session, as any other tool output does — see [Anthropic's privacy policy](https://www.anthropic.com/legal/privacy) for how Claude handles conversations. The plugin stores nothing. A report is written to your machine only if you ask Claude for one.

## Contact

[GitHub Issues](https://github.com/yotsuda/powershell-mcp-security/issues)
