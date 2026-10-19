# powershell-mcp-security

A Claude Code skill that audits and hardens the network security of a Windows, Linux or macOS machine through [PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP) — **with the person at that machine watching every command**.

- **Read-only first.** Inside (effective settings, not just config files) and outside (what the network sees), cross-checked.
- **Fixes only with your approval**, in an order that cannot lock you out.
- **Verified** from outside and again after a reboot — where settings quietly revert.

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/fc9c9d41-5cfd-4771-8741-54f344f18617" />

*The robot in the picture is the AI. It actually runs on your machine and drives the console of the target machine directly, over a TLS-encrypted connection. You talk with the AI and watch the commands it runs on the target scroll by in that console. You can also type in the same console yourself.*

## Requirements

- **Your machine**: Claude Code, PowerShell 7.4+ and PowerShell.MCP 1.16.0 or later. In PowerShell 7:
  ```powershell
  Install-Module PowerShell.MCP
  Register-PwshToClaudeCode
  ```
- **The machine to audit** (if it is not your machine): PowerShell 7.4+ and the **same version** of PowerShell.MCP, and inbound TCP 42777 from your machine. Then, in PowerShell 7 there:
  ```powershell
  Enable-MCPRemoteControl -AllowFrom <your machine's address>
  ```
  Tell Claude the host and the pairing code it prints. If that machine cannot accept inbound connections (NAT, a cloud firewall), Claude can wait on your machine instead and give you an `Enable-MCPRemoteControl -ConnectTo …` line to run there.

Installing PowerShell 7 on a server is itself a change. Remote control is open only while the console runs `Enable-MCPRemoteControl`; end it with `Disable-MCPRemoteControl` or by closing the console. If you would rather not install anything there, the checks under [`checks/`](skills/network-security-audit/checks) are plain commands you can run by hand.

## Install the skill

From the [PowerShell.MCP plugin marketplace](https://github.com/yotsuda/powershell-mcp-plugins):

```
/plugin marketplace add yotsuda/powershell-mcp-plugins
/plugin install powershell-mcp-security@powershell-mcp
```

The skill is then available as `powershell-mcp-security:network-security-audit`. Claude uses it on its own when you ask for a security audit.

## Use

A read-only audit:

> Audit the network security of this server. Read-only first, and check what is visible from outside.

From audit to fixes:

> Audit the network security of this server. Read-only first, and check what is visible from outside. Then fix what you find, with my approval for each change, and verify again after a reboot.

A disposable test machine, including what it can reach on your machine:

> Audit the network security of this Windows Sandbox, read-only. Also check what the sandbox can reach on my machine.

## What it runs and sends

The skill is instructions for Claude plus a read-only PowerShell module, [NetworkSecurityAudit](module/NetworkSecurityAudit), that ships with it. It has no hooks or servers.

- **Downloads**: none on your machine — the module is imported from the plugin folder. On the machine being audited, only if you approve: the same module from the PowerShell Gallery, saved to a temporary folder for the session and removed at cleanup (not installed). If you decline, Claude uses plain commands instead.

- **On the machine being audited**: commands in the PowerShell.MCP console there, shown on its screen as they run. The audit phase only reads (listening ports, firewall rules, sshd and sysctl settings, accounts, update status, logon logs). `authorized_keys` files are read only to list each key's fingerprint, type and comment — the keys themselves are public keys, and their text is neither shown nor sent. Changes are made only after you approve each one; `sudo` passwords are typed by you at that console, never into the chat.
- **On your machine**: TCP connection probes and an SSH login check, sent only to the address of the machine being audited. For a sandbox, a short probe from the sandbox back to your machine's own addresses.
- **Data**: what the commands return goes to your Claude session only. The skill sends nothing anywhere else and keeps no logs.
- **Improving the skill (optional)**: if an audit shows the skill was wrong or missing something, Claude offers to write an issue for this repository. You see the full text first; you submit it yourself in the browser, or Claude files it with `gh` if you are already signed in and approve. Real addresses, names and other personal data are left out.

## Privacy

See [Privacy](PRIVACY.md): the plugin stores nothing and sends nothing outside your Claude session.

## Support

Questions, bug reports and security concerns: [GitHub Issues](https://github.com/yotsuda/powershell-mcp-security/issues).

## Contributing

Checks and fixes for more systems are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Scope

Use it only on machines you own or are authorized to manage. It is not a replacement for continuous monitoring (SOC, EDR); it closes the doors before anyone knocks.

Tested on Ubuntu 24.04 (Hyper-V VM) and Windows 11 (Windows Sandbox). The fix guidance is most complete for Linux; the macOS checks are not yet tested on a real Mac.

## License

[MIT](LICENSE)

---

## 日本語

[PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP) を通して、AI に Windows・Linux・macOS のマシンのネットワークセキュリティを監査させ、対処まで進めるための Claude Code のスキルです。AI が実行するコマンドは、すべて対象のマシンのコンソールに表示され、そこにいる人が見て止められます。

まず読み取りだけで、中（実際に効いている設定）と外（ネットワークから見える状態）を突き合わせます。変更はあなたの承認を得てから、締め出されない順番で行い、外から、そして再起動後にも確かめ直します。

チェック項目や対処の方法の追加を歓迎します（[CONTRIBUTING.md](CONTRIBUTING.md)）。Issue は日本語でも構いません。PR では、スキルのファイル（チェック項目、対処の方法、スクリプト）は AI が読むので英語で書いてください。PR の説明は日本語でも構いません。
