# snapd session-agent user socket trust

Verdict: negative. I did not validate a uid1001/uid1002-to-root LPE in the stock Ubuntu 24.04 Server Docker target through `snapd.session-agent`, per-user runtime sockets, D-Bus activation, or root snapd session-agent calls.

The default package includes `/usr/lib/systemd/user/snapd.session-agent.socket` and `.service`; the socket listens at `%t/snapd-session-agent.socket`, and the service runs `/usr/bin/snap userd --agent`. The D-Bus service `io.snapcraft.SessionAgent` is session-bus activated through systemd, not as root.

Key results from `pocs/snapd_session_agent_probe.sh`:

- Inactive `attacker` uid1001 has no `/run/user/1001` and cannot reach or spoof the agent with `XDG_RUNTIME_DIR`; the client still targets `/run/user/1001/snapd-session-agent.socket`.
- Active `selfauth` uid1002 gets `/run/user/1002` mode `0700` and a user-owned `snapd-session-agent.socket`. Root and uid1002 can query `/v1/session-info`; uid1001 is blocked by runtime directory permissions.
- The real agent's `/v1/service-control` starts only `snap.*` user units through `systemctl --user`. A root client starting a probe `snap.*` unit produced `uid=1002(selfauth)`, not root, and non-`snap.*` unit names were rejected.
- `selfauth` can stop the user socket and replace it with an attacker-controlled Unix socket. Root clients using the session-agent client library connect to that socket as uid0, but this did not become an LPE.
- With the fake uid1002 agent in place, unauthenticated uid1001 and active uid1002 REST requests to root snapd for snap install and user-service control returned `401 Unauthorized` before any session-agent connection. The fake-agent log line count was unchanged across those snapd REST attempts.
- The read-only `/v2/apps?select=service` path returned normally and did not produce root code execution or a privileged trust decision from fake agent data.

Conclusion: the active user's session-agent socket is intentionally user-owned and root snapd clients may connect to it for user-session operations, but the default state does not expose a pre-authorization root trust path. The reachable control surface is bounded to same-user session operations and notifications; privileged snapd REST operations remain authorization-gated before session-agent interaction.
