# OpenSSH Default Local Boundaries - Negative

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, stock Ubuntu 24.04.4 Server default state.

Result: no default OpenSSH-root LPE was validated. The default image has `openssh-client` only; `openssh-server`, `sshd`, `ssh.service`, `ssh.socket`, `/etc/pam.d/sshd`, server host keys, and `sshd_config` are absent. The only privileged OpenSSH-related local helpers found were `ssh-keysign` setuid root, `ssh-agent` setgid `_ssh`, and `utempter` setgid `utmp`; none produced root privilege or a root-controlled file write/read primitive from a normal local user.

Repro helper: `ubuntu24-server-lpe/pocs/openssh_local_probe.sh`.

## Baseline package and reachability proof

```sh
$ docker inspect --format '{{.Name}} {{.Config.Image}} {{.State.Status}} {{.State.StartedAt}}' ubuntu24-server-lpe-target
/ubuntu24-server-lpe-target ubuntu24-server-default-lpe:20260516-standard running 2026-05-16T15:18:50.351426213Z

$ docker exec ubuntu24-server-lpe-target cat /etc/os-release
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo

$ docker exec ubuntu24-server-lpe-target dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' openssh-client openssh-server
openssh-client	1:9.6p1-3ubuntu13.16	ii 
openssh-server		un 

$ docker exec ubuntu24-server-lpe-target apt-cache policy openssh-client openssh-server
openssh-client:
  Installed: 1:9.6p1-3ubuntu13.16
  Candidate: 1:9.6p1-3ubuntu13.16
  Version table:
 *** 1:9.6p1-3ubuntu13.16 100
        100 /var/lib/dpkg/status
openssh-server:
  Installed: (none)
  Candidate: (none)
  Version table:

$ docker exec ubuntu24-server-lpe-target systemctl --no-pager is-enabled ssh.service ssh.socket
not-found
not-found

$ docker exec ubuntu24-server-lpe-target systemctl --no-pager is-active ssh.service ssh.socket
inactive
inactive

$ docker exec ubuntu24-server-lpe-target ss -ltnp
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                                  
LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=97,fd=15))
LISTEN 0      4096      127.0.0.54:53        0.0.0.0:*    users:(("systemd-resolve",pid=97,fd=17))
```

## Server-side boundary checks

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'ls -ld /etc/ssh /etc/ssh/* 2>&1; grep -RIn "^[[:space:]]*[^#[:space:]]" /etc/ssh 2>/dev/null || true'
drwxr-xr-x 3 root root 4096 May 16 10:22 /etc/ssh
-rw-r--r-- 1 root root 1649 Apr 28 00:29 /etc/ssh/ssh_config
drwxr-xr-x 2 root root 4096 Apr 28 00:29 /etc/ssh/ssh_config.d
/etc/ssh/ssh_config:19:Include /etc/ssh/ssh_config.d/*.conf
/etc/ssh/ssh_config:21:Host *
/etc/ssh/ssh_config:51:    SendEnv LANG LC_*
/etc/ssh/ssh_config:52:    HashKnownHosts yes
/etc/ssh/ssh_config:53:    GSSAPIAuthentication yes

$ docker exec ubuntu24-server-lpe-target sh -lc 'ls -l /usr/sbin/sshd /etc/ssh/sshd_config /etc/pam.d/sshd /etc/ssh/ssh_host_* 2>&1'
ls: cannot access '/usr/sbin/sshd': No such file or directory
ls: cannot access '/etc/ssh/sshd_config': No such file or directory
ls: cannot access '/etc/pam.d/sshd': No such file or directory
ls: cannot access '/etc/ssh/ssh_host_*': No such file or directory
```

`AuthorizedKeysCommand`, `AuthorizedKeysFile`, `PermitUserEnvironment`, privilege separation, and SSH PAM/session environment were not reachable because no default `sshd` package, binary, PAM stack, unit, socket, listener, or host keys exist in this image. Attacker-controlled `authorized_keys` and `authorized_keys2` symlinks therefore had no root daemon to consume them:

```sh
$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- sh -lc 'mkdir -p "$HOME/.ssh"; ln -sf /etc/shadow "$HOME/.ssh/authorized_keys"; ln -sf /etc/shadow "$HOME/.ssh/authorized_keys2"; ls -l "$HOME/.ssh"; rm -f "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys2"; rmdir "$HOME/.ssh" 2>/dev/null || true; find "$HOME" -maxdepth 2 \( -name authorized_keys -o -name authorized_keys2 \) -print'
total 0
lrwxrwxrwx 1 attacker attacker 11 May 16 15:30 authorized_keys -> /etc/shadow
lrwxrwxrwx 1 attacker attacker 11 May 16 15:30 authorized_keys2 -> /etc/shadow
```

## Client/helper boundary checks

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'stat -c "%A %a %U %G %n" /usr/bin/ssh /usr/bin/ssh-agent /usr/bin/scp /usr/bin/sftp /usr/lib/openssh/ssh-keysign /usr/lib/openssh/ssh-pkcs11-helper /usr/lib/openssh/ssh-sk-helper /usr/lib/aarch64-linux-gnu/utempter/utempter'
-rwxr-xr-x 755 root root /usr/bin/ssh
-rwxr-sr-x 2755 root _ssh /usr/bin/ssh-agent
-rwxr-xr-x 755 root root /usr/bin/scp
-rwxr-xr-x 755 root root /usr/bin/sftp
-rwsr-xr-x 4755 root root /usr/lib/openssh/ssh-keysign
-rwxr-xr-x 755 root root /usr/lib/openssh/ssh-pkcs11-helper
-rwxr-xr-x 755 root root /usr/lib/openssh/ssh-sk-helper
-rwxr-sr-x 2755 root utmp /usr/lib/aarch64-linux-gnu/utempter/utempter

$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- ssh -G -T localhost | egrep '^(host |user |hostname |port |enablesshkeysign |hostbasedauthentication |globalknownhostsfile |userknownhostsfile |hashknownhosts |sendenv |forwardagent |requesttty |gssapiauthentication )'
host localhost
user attacker
hostname localhost
port 22
enablesshkeysign no
gssapiauthentication yes
hashknownhosts yes
hostbasedauthentication no
requesttty false
globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2
userknownhostsfile /home/attacker/.ssh/known_hosts /home/attacker/.ssh/known_hosts2
sendenv LANG
sendenv LC_*
forwardagent no

$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- /usr/lib/openssh/ssh-keysign
ssh-keysign not enabled in /etc/ssh/ssh_config

$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- sh -lc 'tmp=$(mktemp -d /tmp/openssh-keysign-env.XXXXXX); trap "rm -rf \"$tmp\"" EXIT; printf x > "$tmp/preload.so"; HOME="$tmp" PATH="$tmp:$PATH" LD_PRELOAD="$tmp/preload.so" SSH_AUTH_SOCK="$tmp/sock" /usr/lib/openssh/ssh-keysign'
ssh-keysign not enabled in /etc/ssh/ssh_config
```

The setuid root `ssh-keysign` path is the highest-signal scanner finding, but default `EnableSSHKeysign no`, `HostbasedAuthentication no`, and absent `/etc/ssh/ssh_host_*` keys block the signing path before attacker-controlled path/env parsing becomes useful.

```sh
$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- ssh-agent sh -c 'id; printf "SSH_AUTH_SOCK=%s\nSSH_AGENT_PID=%s\n" "$SSH_AUTH_SOCK" "$SSH_AGENT_PID"; stat -c "%A %a %U %G %n" "$(dirname "$SSH_AUTH_SOCK")" "$SSH_AUTH_SOCK"; ps -o pid,user,group,euid,egid,comm -p "$SSH_AGENT_PID"; ssh-add -l 2>&1'
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
SSH_AUTH_SOCK=/tmp/ssh-2f8hduXBOaNJ/agent.3799
SSH_AGENT_PID=3800
drwx------ 700 attacker attacker /tmp/ssh-2f8hduXBOaNJ
srw------- 600 attacker attacker /tmp/ssh-2f8hduXBOaNJ/agent.3799
    PID USER     GROUP     EUID  EGID COMMAND
   3800 attacker attacker  1001  1001 ssh-agent
The agent has no identities.

$ docker exec ubuntu24-server-lpe-target runuser -u attacker -- sh -lc 'mkdir -p "$HOME/.ssh"; ln -sf /etc/shadow "$HOME/.ssh/known_hosts"; ssh -oBatchMode=yes -oConnectTimeout=1 -vvv 127.0.0.1 true 2>&1 | sed -n "/known_hosts/p;/Permission denied/p;/Connection refused/p"; rm -f "$HOME/.ssh/known_hosts"; rmdir "$HOME/.ssh" 2>/dev/null || true'
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts' -> '/home/attacker/.ssh/known_hosts'
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts2' -> '/home/attacker/.ssh/known_hosts2'
debug1: connect to address 127.0.0.1 port 22: Connection refused
ssh: connect to host 127.0.0.1 port 22: Connection refused
```

`ssh-agent` executes as the caller and creates a caller-owned `0700` socket directory and `0600` socket, so the `_ssh` setgid file mode did not become root. `known_hosts` is expanded under the attacker's home by an unprivileged client; with no SSH listener, no privileged root read path exists.

## utempter/login tie-in

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'ldd /usr/bin/ssh | grep -i utempter || true; ldd /usr/lib/openssh/ssh-keysign | grep -i utempter || true; test -e /etc/X11/Xsession.options; echo xsession_options_exists=$?; systemctl --no-pager --user --machine selfauth@ status ssh-agent.service 2>&1 || true'
xsession_options_exists=1
○ ssh-agent.service - OpenSSH Agent
     Loaded: loaded (/usr/lib/systemd/user/ssh-agent.service; static)
     Active: inactive (dead)
       Docs: man:ssh-agent(1)

$ docker exec ubuntu24-server-lpe-target sh -lc 'command -v login; stat -c "%A %a %U %G %n" /bin/login /usr/bin/login 2>&1; ldd /bin/login 2>&1 | grep -i utempter || true; dpkg -S /bin/login /usr/bin/login 2>&1'
/usr/bin/login
-rwxr-xr-x 755 root root /bin/login
-rwxr-xr-x 755 root root /usr/bin/login
dpkg-query: no path found matching pattern /bin/login
login: /usr/bin/login
```

`utempter` is present only as setgid `utmp`; neither `ssh` nor `ssh-keysign` links it. The user `ssh-agent.service` is static/inactive for `selfauth`, and the X11 condition file is absent (`test` exit `1`), consistent with no desktop session assumption.

## Cleanup

Probe cleanup removed the user symlinks, temporary keysign directory, and transient agent state. Verification:

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'find /tmp -maxdepth 1 \( -name "openssh-keysign-env.*" -o -name "ssh-*" \) -printf "%p\n"'

$ docker exec ubuntu24-server-lpe-target sh -lc 'find /home/attacker -maxdepth 2 -name known_hosts -o -name authorized_keys -o -name authorized_keys2 -print'

$ docker exec ubuntu24-server-lpe-target pgrep -a ssh-agent
```

All three cleanup verification commands produced no output.

## Why scanners might miss or mis-rank this

Package-name scanners may assume "Ubuntu Server" implies a reachable `openssh-server`; this image does not install it by default. SUID scanners may flag `/usr/lib/openssh/ssh-keysign`, but the default global client config disables it and host keys are absent. Config scanners may report `~/.ssh/authorized_keys`, `authorized_keys2`, or `known_hosts` path-following risk without checking that no root `sshd` exists to read attacker-controlled authorized-key paths and that the client-side `known_hosts` path is read by an unprivileged `ssh` process.
