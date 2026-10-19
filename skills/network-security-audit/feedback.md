# Feedback to the skill

The skill gets better from real audits. When an audit shows the skill was wrong or missing something, offer to report it as an issue on https://github.com/yotsuda/powershell-mcp-security. An issue, not a pull request: the maintainer folds issues into the skill, so many reports never conflict with each other. Nothing is published without the user's approval.

## What is worth an issue

- A check that misled you: a command that failed, printed nothing where the file said it would, or whose reading was wrong.
- A gap: something you had to work out yourself that the next audit should not have to (a missing check, an exception, a tool that behaves differently on this OS version).
- A fix that did not work as written, or a step that would have locked someone out.
- A check the user wished the skill had made — something they worry about that it does not look at.

Not worth one: style, rewording, findings about this particular machine. One topic per issue.

## No real addresses, no personal data

An issue is public and permanent. It must not contain any real IP address, host name or personal data — from the audited machine, this machine or anywhere else in the session: addresses (IPv4, IPv6, MAC), host and domain names, user and account names, email addresses, key fingerprints and comments, log lines, paths under home directories (`C:\Users\<name>`, `/home/<name>`), organization and network names, pairing codes. Use documentation values instead (`192.0.2.10`, `2001:db8::1`, `host1`, `alice`, `example.com`). Describe what you observed in general terms ("on Ubuntu 24.04, ufw re-applies its own sysctl.conf at boot").

Before showing the issue to the user, search its title and body for addresses and names and replace any you find:

```powershell
$text | Select-String -AllMatches '\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b|[0-9a-f]{2}([-:][0-9a-f]{2}){5}|\S+@\S+\.\w+|SHA256:\S+|\\Users\\|/home/' |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

Anything left must be a documentation value (192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::) or a well-known range used as an example (`172.16.0.0/12`, `fe80::/10`). Tell the user you checked.

## Writing it

In English, so the maintainer can paste from it into the skill:

- **Title**: the problem in one line ("linux.md: InRelease mtime is not when the lists were fetched").
- **Observed**: what happened, on which OS and version, PowerShell.MCP version, the skill version (`version` in `.claude-plugin/plugin.json`).
- **Expected / suggested change**: what the skill should say instead — name the file and section, and give the replacement text or command when you have one.
- **How you verified it**: the command and the (scrubbed) output that shows it.

## Steps

Everything runs on **this machine** (`execute_command`), never on the target.

1. **Propose** — after the report, say in a few lines what you would report and why, and ask whether to file an issue. If the user says no, stop.
2. **Look for duplicates** — search the repository's issues for the topic (`gh issue list -R yotsuda/powershell-mcp-security --state all --search "<keywords>"` if `gh` is installed; otherwise https://github.com/yotsuda/powershell-mcp-security/issues?q=<keywords>). If one covers it, show it to the user and offer to add what is new as a comment instead.
3. **Show** — the title and body, after the search above. Change what the user asks.
4. **File it** — the user decides how:
   - **In the browser (no install, no sign-in for you)**: build `https://github.com/yotsuda/powershell-mcp-security/issues/new?title=<url-encoded>&body=<url-encoded>` with `[uri]::EscapeDataString()` and give it to the user (or open it with `Start-Process` on Windows, `open` on macOS, `xdg-open` on Linux). They read it there and submit it themselves. Keep the URL under about 8,000 characters; if it is longer, shorten the body.
   - **With `gh`**, if it is installed and `gh auth status` shows the user signed in: `gh issue create -R yotsuda/powershell-mcp-security --title … --body-file …`, only after the user approves the text. Do not install `gh` or sign in for this; never handle a token.

   Give the user the issue's URL.
