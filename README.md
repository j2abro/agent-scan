# agent-scan

Measure your AI agent's blast radius.

An agent runs with whatever access the process around it has. For example, on a developer
laptop that is usually your whole identity: SSH keys, cloud credentials,
documents, and unrestricted outbound network. On a production agent running in a sandbox you'd expect less access. 
This script measures that access from the point of view of where the agent runs. You can run this script to verify they have limited access. Think of it as an outbound pentest to determine the blast radius if your agent goes rogue.

## How to run

```bash
python3 scan.py --report
```

One file, python 3 standard library, nothing to install. Add `--out report.txt`
to keep the result so two runs can be diffed.

## Threat model

The categories come from an interactive agent threat model you can configure
and read here:

**https://j2abro.github.io/agent-threat-model/**

It covers containment and runtime, model and inference, data access, tools and
external systems, approval and controls, and adversarial inputs. This script
tests the parts you can measure from inside a running agent. It does not test
prompt injection or anything about model behaviour.

## The tests

**Identity.** Who the agent runs as, and what that account is allowed to do.

- Is it root, or a regular user? (`uid`, `gid`)
- Does it hold any of root's individual powers, even as a regular user?
  (`CapEff`). Root's privileges are split into about 40 of these. One of them
  lets a process ignore file permissions, so mode 600 files owned by someone
  else become readable.
- Can it gain privilege by running another program? (`NoNewPrivs`)
- Is the kernel filtering which system calls it may make? (`seccomp`)
- Does anything in the environment say it is sandboxed?

**Credentials.** Read access to 13 paths:

```
~/.ssh      ~/.aws       ~/.config/gh   ~/.docker/config.json
~/.kube     ~/.gnupg     ~/.netrc       ~/.npmrc
~/.claude   ~/Library/Keychains         /Library/Keychains
/etc/shadow             /proc/1/environ
```

Plus environment variable names matching `KEY`, `TOKEN`, `SECRET`, `PASSWORD`,
`PASSWD`, `CRED`, `API`, `AUTH`, `PRIVATE`, `SESSION`. Values are never read.
The name and length are reported, and values under 10 characters are called out
as flags rather than secrets.

Plus `SSH_AUTH_SOCK`, checked for a live socket. A live agent socket
authenticates as you without any key file being read, so no filesystem rule
closes it.

**Personal data.** Read access to 9 paths:

```
~/Documents   ~/Downloads   ~/Desktop   ~/Pictures   /Volumes
~/Library/Mail   ~/Library/Messages   ~/Library/Safari
~/Library/Application Support/AddressBook
```

**Filesystem reach.** Read and write on 15 paths:

```
/etc  /tmp  /usr  /var  /dev/null  /Users  /root  /home
/opt  /srv  /mnt  /run  /var/lib   /var/tmp  ~/.gitconfig
```

Write tests create a file named `.scanprobe` and delete it.

**Escape routes.** Read access to 5 paths, plus the cloud metadata endpoint
below:

```
/var/run/docker.sock   /run/docker.sock   /proc/mounts   /sys   /boot
```

A docker socket is root on the host. A metadata endpoint hands out cloud
credentials with no authentication.

**Network egress.** 6 requests:

```
api.github.com:443/zen               example.com:443/
api.github.com:443/users/j2abro      raw.githubusercontent.com:443/
api.github.com:80/zen                169.254.169.254:80/latest/meta-data/
```

The three `api.github.com` requests are the same host with a different path
and a different port. That shape separates a real allowlist from a sandbox
that blocks everything.

**Execution.** Which of these are present:

```
python3  bash  sh  curl  wget  git  ssh  docker  apt-get  pip3  nc
```

An egress hole matters more when there is a client to use it.

## Outcomes

Each test reports the mechanism, not just pass or fail:

| Outcome | Means | Layer |
|---|---|---|
| `allow` | it worked | none |
| `denied` | refused, errno 13 | unix permissions, or Landlock |
| `eperm` | refused, errno 1 | macOS TCC, or a seatbelt sandbox |
| `absent` | the path does not exist | never mapped in, not merely blocked |
| `blocked` | connection never opened | network policy, at connect |
| `refused` | connected, request refused | network policy, at layer 7 |

## Context

Three axes, reported separately:

| Axis | Values |
|---|---|
| platform | `macos`, `linux` |
| containment | `vanilla`, `container`, `kubernetes`, `openshell` |
| harness | `none`, `claude-code`, `cursor`, `ci` |

`vanilla` means nothing is containing the agent, for example, it's just running on your personal laptop.

## What it does not do

- Reads no credential values.
- Sends nothing anywhere. No telemetry. The only outbound requests are the six
  egress probes.
- Writes one file, `.scanprobe`, and deletes it.
- Makes no security claim. It measures reach, not behaviour.

## Limits

Reach outward cannot be enumerated, only tested against a list. Filesystem
grants can be per path, so a deep path may be readable while every parent is
denied, and walking the tree will not find it. The candidate list above is
what the results depend on.

Facts about the agent's own context can be enumerated in full: environment,
mounts, identity, capabilities.

A positive result is definitive. A negative one is not. "It read `~/.ssh`"
needs no baseline. "It was blocked" might be a control or a host that did not
answer. To attribute a denial to a layer, run twice with the containment on
and off. Identical output means that layer is doing nothing.

## Checking a sandbox against its policy

With [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell), expectations can
be computed from the policy instead of written by hand:

```bash
./scan.sh <sandbox>
```

Deny is the default expectation and the policy's grants are the exceptions, so
one run catches a rule that is not being enforced and a grant nobody intended.
Exits non-zero on mismatch. Needs the `openshell` CLI and `ruby`.

## License

MIT
