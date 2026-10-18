# Fixing safely

Only after the user approves a specific plan. For each change state: what, why (which finding), how to verify, how to undo.

## Before the first change

- **Name the lifelines**: the connections the user and you depend on (SSH from the management network, the PowerShell.MCP remote port 42777, RDP, a console in a hypervisor). Every change must keep them working.
- **Ask whether there is an out-of-band way in** (VM console, iLO/iDRAC, physical access). If there is none, be twice as careful with firewall and SSH changes.
- **Back up** every file before editing it (`cp -a file file.bak.<date>`, `Copy-Item`).

## Order that cannot lock anyone out

1. **Firewall**: add the allow rules for the lifelines **first**, then set default deny / enable the firewall. Never the reverse.
2. **Scope allow rules to what does not move.** DHCP and virtual switch subnets change (a Hyper-V Default Switch or WSL gets a new subnet after a host reboot). If the management address is not stable, allow a wider private range (e.g. `172.16.0.0/12`) and say why — check it does not also cover a network you did not mean to trust.
3. **SSH**: write a drop-in that is read **before** others (e.g. `/etc/ssh/sshd_config.d/01-hardening.conf` — sshd keeps the first value). Run `sudo sshd -t` before reloading. Reload, do not restart. Exception: on Ubuntu 22.10 and later sshd is socket-activated, so a change of `Port` or `ListenAddress` needs `systemctl daemon-reload` and `systemctl restart ssh.socket` — a reload keeps the old listener, and the outside check then shows the old port. **Keep the current session open** and prove that a new login still works before anything else — the key login in [checks/outside.md](checks/outside.md#does-key-login-still-work), or the user opens a second session. A drop-in written by cloud-init (`50-cloud-init.conf`) may be edited in place: cloud-init writes it on an instance's first boot only — the reboot check shows whether it came back.
4. **sudoers**: edit only with `visudo` (`visudo -c` to validate). Do not remove the user's own sudo access.
5. **Kernel settings**: a file in `/etc/sysctl.d/` and `sudo sysctl --system`. Set `all`, `default` **and** each existing interface by name (e.g. `net.ipv6.conf.eth0.accept_redirects = 0`) — for IPv6 `accept_redirects` only the interface value counts, and `default` does not reach a NIC that existed before systemd-sysctl ran (see [checks/linux.md](checks/linux.md#kernel-network-settings)). If ufw is installed, it re-applies `/etc/ufw/sysctl.conf` when it starts and wins: change the same keys there too, or the reboot check will find them reverted.
6. **Services**: stop and disable only what the user confirms is unused.
7. **authorized_keys**: remove only keys the user names. Show each key by type, fingerprint and comment (`ssh-keygen -lf`), never the key text. Back up, remove the line (`sed -i '/<unique part of the comment>/d'`; CRLF endings: `sed -i 's/\r$//'`), check with `ssh-keygen -lf` that the remaining keys are the expected ones, and prove the key login still works — the session you are in does not prove it.

## Never do

- Change passwords for the user, or ask for them in the chat.
- Open firewall ports or start remote access services to make your own work easier.
- Run destructive commands (delete users, wipe rules with no allow rule in place, `iptables -F` with a DROP policy).

## Verify

1. Re-run the inside check for each finding.
2. Re-run the outside checks ([checks/outside.md](checks/outside.md)), including a real login over the lifelines.
3. With the user's consent, reboot, reconnect, and run 1 and 2 again. Report anything that reverted and which component reverted it.

When asking for the reboot, tell the user in one go what it takes afterwards:

- remote control ends: they run `Enable-MCPRemoteControl` there again and give you the new code — and the **address, which may have changed** (DHCP, a Hyper-V Default Switch). Probe the new address from outside: the old one answers nothing, and an all-Filtered result would read as a pass.
- the sudo credentials are gone: `sudo -v` again, with a password prompt at the target's console.
