#!/usr/bin/env python3
"""What can this agent actually reach?

Two modes, one set of probes.

  ./scan.sh <sandbox>        assert: expectations computed from the sandbox
                             policy. Catches rules that are not enforced AND
                             unintended grants.
  python3 scan.py --report   enumerate: no policy needed. Runs anywhere an
                             agent runs, including an unsandboxed laptop,
                             a CI runner or a pod. Read-only, writes nothing.

ONE candidate list, selected by platform. Deny is the default expectation and
the policy's grants are the exceptions, so both failure directions surface:

    expected allow, got deny   a rule you wrote is not enforced
    expected deny,  got allow  an UNINTENDED GRANT

Outcomes name the mechanism, because "deny" is too coarse to be evidence:
    allow    succeeded
    denied   filesystem refused          (Landlock or unix perms)
    absent   path does not exist         (never mapped in)
    eperm    refused by an OS policy layer (macOS TCC, a seatbelt sandbox),
             NOT by unix permissions. errno 1 rather than 13.
    blocked  connection never opened     (network policy, at connect)
    refused  connected, request refused  (network policy, at layer 7)

Categories, the capability surface. Each candidate carries one:
    ident   who am I and with what privilege
    secret  credentials reachable, including delegated auth
    data    personal or business content readable, so exfiltratable
    fs      filesystem reach, structurally
    net     network egress
    escape  routes out of the box: sockets, mounts, metadata endpoints
    exec    what can be run

LIMIT: outward reach is not enumerable, only testable against a list, because
Landlock grants are per path and a deep path can be granted while every parent
is denied. Inward facts (env, mounts, identity) ARE fully enumerable. The list
is the asset, not the code.
"""
import fnmatch
import json
import os
import shutil
import sys
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
REPORT_ONLY = "--report" in sys.argv

# --out FILE writes everything to a file as well as the screen, so a run is
# keepable and two runs can be diffed.
OUT = None
if "--out" in sys.argv:
    OUT = open(sys.argv[sys.argv.index("--out") + 1], "w")
    _print = print
    def print(*a, **k):                      # noqa: A001
        _print(*a, **k)
        _print(*a, **{**k, "file": OUT})

try:
    POLICY = json.load(open("policy.json"))
except Exception:
    if not REPORT_ONLY:
        sys.exit("no policy.json. Use ./scan.sh <sandbox>, or --report to "
                 "enumerate with no policy (laptop, CI, pod).")
    POLICY = {}

# --- where are we ----------------------------------------------------------
# Three independent axes. Conflating them was a mistake: "macos" says which
# paths exist, not what is containing you, and an agent on a bare Mac is a
# different problem from one under a harness that mediates its tool calls.

def platform():
    """Which paths exist. Picks the candidate list."""
    return {"darwin": "macos", "linux": "linux"}.get(sys.platform, sys.platform)

def containment():
    """What, if anything, is enforcing. 'vanilla' means nothing is."""
    if os.environ.get("OPENSHELL_SANDBOX"):            return "openshell"
    if os.environ.get("KUBERNETES_SERVICE_HOST"):       return "kubernetes"
    if os.path.exists("/.dockerenv"):                   return "container"
    try:
        cg = open("/proc/1/cgroup").read()
        if any(x in cg for x in ("docker", "containerd", "kubepods")):
            return "container"
    except Exception:
        pass
    return "vanilla"

def harness():
    """What is mediating tool calls, and putting its own secrets in the env."""
    for marker, name in (("CLAUDE_CODE_SESSION_ID", "claude-code"),
                          ("CURSOR_TRACE_ID", "cursor"),
                          ("GITHUB_ACTIONS", "github-actions"),
                          ("CI", "ci")):
        if os.environ.get(marker):
            return name
    return "none"

PLATFORM, CONTAIN, HARNESS = platform(), containment(), harness()
CTX = PLATFORM          # the candidate list still keys off platform

# --- candidates, by platform ----------------------------------------------
CORE = [("/etc", "fs"), ("/tmp", "fs"), ("/usr", "fs"), ("/var", "fs"),
        ("/dev/null", "fs"), ("/var/run/docker.sock", "escape")]

NIX = [("/root", "fs"), ("/home", "fs"), ("/opt", "fs"), ("/srv", "fs"),
       ("/mnt", "fs"), ("/boot", "escape"), ("/sys", "escape"),
       ("/run", "fs"), ("/var/lib", "fs"), ("/var/tmp", "fs"),
       ("/etc/shadow", "secret"), ("/proc/1/environ", "secret"),
       ("/proc/mounts", "escape"), ("/run/docker.sock", "escape")]

MAC = [("/Users", "fs"), ("/Volumes", "data"),
       ("/Library/Keychains", "secret")]

# relative to $HOME, which is where credentials actually live on a workstation
HOMEPATHS = [(".ssh", "secret"), (".aws", "secret"), (".config/gh", "secret"),
             (".docker/config.json", "secret"), (".kube", "secret"),
             (".gnupg", "secret"), (".netrc", "secret"), (".npmrc", "secret"),
             (".claude", "secret"), ("Library/Keychains", "secret"),
             (".gitconfig", "fs"),
             # macOS protects these independently of any sandbox, via TCC.
             # If a harness sandbox restricts anything on a Mac, it shows here.
             ("Documents", "data"), ("Downloads", "data"),
             ("Desktop", "data"), ("Library/Mail", "data"),
             ("Library/Messages", "data"), ("Pictures", "data"),
             ("Library/Safari", "data"),
             ("Library/Application Support/AddressBook", "data")]

FS_CANDIDATES = CORE + (MAC + NIX if PLATFORM == "macos" else NIX)
# $HOME credentials are the point on an uncontained host. Inside a sandbox or
# container there is normally nothing there, but probe anyway: a mounted home
# directory is exactly the misconfiguration worth catching.
FS_CANDIDATES += [(os.path.join(HOME, p), c) for p, c in HOMEPATHS]

NET_CANDIDATES = [
    ("api.github.com", 443, "/zen", "net"),
    ("api.github.com", 443, "/users/j2abro", "net"),
    ("api.github.com", 80, "/zen", "net"),
    ("example.com", 443, "/", "net"),
    ("raw.githubusercontent.com", 443, "/", "net"),
    ("169.254.169.254", 80, "/latest/meta-data/", "escape"),   # cloud IMDS
]

EXEC_CANDIDATES = ["python3", "bash", "sh", "curl", "wget", "git", "ssh",
                   "docker", "apt-get", "pip3", "nc"]

# --- what the policy says to expect ---------------------------------------
FS = POLICY.get("filesystem_policy", {})
READ_ONLY = set(FS.get("read_only", []))
READ_WRITE = set(FS.get("read_write", []))
if FS.get("include_workdir", "filesystem_policy" not in POLICY):
    READ_WRITE.add(os.getcwd())

# Landlock granting a path does not override unix permissions. Both must allow.
ALSO_DENIED_BY_UNIX = {"/etc/shadow", "/etc/gshadow", "/proc/1/environ"}

def granted(path, writable=False):
    pool = READ_WRITE if writable else READ_ONLY | READ_WRITE
    real = os.path.realpath(path)     # /bin, /lib, /sbin are symlinks into /usr
    return any(real == g or real.startswith(g.rstrip("/") + "/") for g in pool)

def expect_fs(path, writable):
    """A grant means the policy permits access, not that the path exists.

    Inside the sandbox $HOME is /sandbox, which IS granted, so ~/.ssh
    computes to "allow" while the file simply is not there. Landlock skips
    missing paths in both compatibility modes, so `absent` is never a policy
    failure. Existence cannot be tested separately: os.path.exists on a
    denied path also returns False, because the stat itself is refused.
    """
    if path in ALSO_DENIED_BY_UNIX:        return {"denied", "absent", "eperm"}
    if granted(path, writable):            return {"allow", "absent"}
    return {"denied", "absent", "eperm"}

def expect_net(host, port, path):
    for rule in (POLICY.get("network_policies") or {}).values():
        for ep in rule.get("endpoints", []):
            if ep.get("host") != host:                                continue
            if port not in (ep.get("ports") or [ep.get("port")]):     continue
            if ep.get("access") in ("read-only", "read-write", "full"):
                return {"allow"}
            for r in ep.get("rules") or []:
                a = r.get("allow", {})
                if a.get("method") in ("GET", "*") and \
                   fnmatch.fnmatch(path, a.get("path", "")):
                    return {"allow"}
            return {"refused"}      # endpoint allowed, this request is not
    return {"blocked"}              # endpoint not allowed at all

# --- operations ------------------------------------------------------------
def do_read(p):  os.listdir(p) if os.path.isdir(p) else open(p, "rb").read(1)
def do_write(p):
    if os.path.isdir(p):
        t = os.path.join(p, ".scanprobe"); open(t, "w").write("x"); os.unlink(t)
    else:
        open(p, "r+b")              # read+write, does NOT truncate
def do_http(host, port, path):
    scheme = "https" if port == 443 else "http"
    urllib.request.urlopen(f"{scheme}://{host}:{port}{path}", timeout=8).read()

def classify(e):
    if e is None:                             return "allow"
    if isinstance(e, urllib.error.HTTPError): return "refused"
    if isinstance(e, urllib.error.URLError):  return "blocked"
    if isinstance(e, FileNotFoundError):      return "absent"
    if isinstance(e, PermissionError):
        # errno distinguishes the layer: EACCES (13) is unix permissions or
        # Landlock; EPERM (1) on macOS is TCC or a seatbelt sandbox. Worth
        # separating, because only one of them is something you configured.
        return "eperm" if getattr(e, "errno", None) == 1 else "denied"
    return type(e).__name__

# --- assert mode -----------------------------------------------------------
# p=p pins the loop variable into each lambda; without it every lambda would
# close over the same name and use the final value.
def run_asserts():
    checks = []
    for p, cat in FS_CANDIDATES:
        checks.append((expect_fs(p, False), cat, f"read  {p}", lambda p=p: do_read(p)))
        checks.append((expect_fs(p, True), cat, f"write {p}", lambda p=p: do_write(p)))
    for h, port, path, cat in NET_CANDIDATES:
        checks.append((expect_net(h, port, path), cat, f"GET {h}:{port}{path}",
                       lambda h=h, p=port, q=path: do_http(h, p, q)))

    fails = unintended = 0
    print(f"platform={PLATFORM}  containment={CONTAIN}  harness={HARNESS}"
          f"   {len(checks)} checks from policy.json\n")
    print(f"{'CAT':7} {'CHECK':40} {'EXPECT':14} {'ACTUAL':8} RESULT")
    for want, cat, name, fn in checks:
        try:
            fn(); err = None
        except Exception as e:
            err = e
        actual = classify(err)
        ok = actual in want
        if not ok:
            fails += 1
            unintended += actual == "allow"
        flag = "  <- UNINTENDED GRANT" if not ok and actual == "allow" else ""
        print(f"{cat:7} {name:40} {'|'.join(sorted(want)):14} {actual:8} "
              f"{'ok' if ok else 'FAIL'}{flag}")
    print(f"\n{len(checks)} checks, {fails} mismatched, {unintended} unintended grant(s)")
    return fails

# --- report mode -----------------------------------------------------------
SECRETISH = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CRED",
             "API", "AUTH", "PRIVATE", "SESSION")
# Below this, a value is a flag or a timeout rather than a secret. It does not
# make the remaining matches credentials, it only removes the obvious noise.
CRED_MIN_LEN = 10
# Variables a harness or a sandbox injects for its own plumbing: IPC tokens,
# session identifiers, proxy auth for an egress filter. They match the name
# heuristic but they are not credentials to external services, and counting
# them as exposure gets the direction backwards. What matters is the group
# that was already in your own environment.
PLUMBING_PREFIX = ("CLAUDE_CODE_", "CLAUDECODE", "CURSOR_", "TERM_SESSION",
                   "CLOUDSDK_PROXY", "GITHUB_ACTIONS", "CI_", "API_TIMEOUT",
                   "USE_LOCAL_OAUTH", "USE_STAGING_OAUTH")

def run_report():
    print("=" * 70)
    print(f"AGENT CONTEXT REPORT")
    print(f"  platform    {PLATFORM}")
    print(f"  containment {CONTAIN}"
          f"{'   (no marker found; the verdict decides from measurements)' if CONTAIN == 'vanilla' else ''}")
    print(f"  harness     {HARNESS}")
    print("=" * 70)

    print("\n[ident] identity and privilege")
    print(f"  uid/gid        {os.getuid()}:{os.getgid()}")
    print(f"  cwd            {os.getcwd()}")
    print(f"  sandbox marker {os.environ.get('OPENSHELL_SANDBOX', 'none')}")
    try:
        want = ("CapEff", "Seccomp", "NoNewPrivs")
        for line in open("/proc/self/status"):
            if line.split(":")[0] in want:
                print(f"  {line.strip()}")
    except Exception:
        print("  caps/seccomp   unavailable (not Linux)")

    # This test matches variable NAMES against SECRETISH. It never reads a
    # value. So a match means "the name looks like a credential", which has
    # false positives (API_TIMEOUT_MS matches "API") and false negatives (a
    # DATABASE_URL with a password in the connection string matches nothing).
    # Value LENGTH is the cheap discriminator: 0 or 1 character is a flag.
    env = os.environ
    hits = sorted(k for k in env if any(s in k.upper() for s in SECRETISH))
    plausible = [k for k in hits if len(env[k]) >= CRED_MIN_LEN]
    yours = [k for k in plausible if not k.startswith(PLUMBING_PREFIX)]
    plumbing = [k for k in plausible if k.startswith(PLUMBING_PREFIX)]
    print(f"\n[secret] environment: {len(env)} vars, {len(hits)} name matches")
    print(f"  (names matched against {'/'.join(SECRETISH)}; values never read)")
    print(f"\n  YOURS, {len(yours)} credential-length. These were in your own")
    print("  environment and every process you start inherits them:")
    for k in yours:
        print(f"    {k:36} {len(env[k]):>4} chars")
    if plumbing:
        print(f"\n  Harness or sandbox plumbing, {len(plumbing)}. Session ids, IPC")
        print("  tokens, proxy auth for the egress filter. Not external credentials:")
        for k in plumbing:
            print(f"    {k:36} {len(env[k]):>4} chars")
    short = [k for k in hits if k not in plausible]
    if short:
        print(f"\n  Too short to be secrets, {len(short)}: {', '.join(short)}")

    sock = env.get("SSH_AUTH_SOCK")
    if sock:
        live = os.path.exists(sock)
        print(f"\n[secret] SSH agent socket {'live' if live else 'declared but absent'}")
        if live:
            print("  Authenticates as you without reading any key file, so a")
            print("  filesystem rule does not close it.")

    print("\n[escape] mounts")
    found = 0
    for f in ("/proc/mounts", "/etc/mtab"):
        try:
            for line in open(f):
                if any(x in line for x in ("docker.sock", "/host", "/var/run")):
                    print(f"  {line.split()[1]:36} {line.split()[0]}")
                    found += 1
            break
        except Exception:
            continue
    if not found:
        print("  none, or mount table unavailable")

    print("\n[fs] reachable paths")
    for p, cat in FS_CANDIDATES:
        try:
            do_read(p)
            print(f"  {cat:7} {p}")
        except Exception:
            pass

    # What is actually stopping it, and which layer. EPERM means an OS policy
    # layer (macOS TCC, a seatbelt sandbox), not unix permissions.
    eperms = []
    for path, cat in FS_CANDIDATES:
        try:
            do_read(path)
        except OSError as e:
            if getattr(e, "errno", None) == 1:
                eperms.append(path.replace(HOME, "~"))
        except Exception:
            pass
    if eperms:
        print("\n[fs] refused by an OS policy layer, not unix permissions")
        for e in eperms:
            print(f"  eperm   {e}")

    # Writability is where a seatbelt or harness sandbox shows up at all,
    # since those restrict writes far more than reads. Creates a file named
    # .scanprobe and removes it again, nothing else.
    print("\n[fs] writable (probe file created and removed)")
    writable = []
    for p in [os.getcwd(), "/tmp", HOME, "/etc", "/usr/local", "/var/tmp",
              os.path.join(HOME, ".config"), os.path.join(HOME, ".claude")]:
        try:
            do_write(p); r = "WRITABLE"; writable.append(p)
        except Exception as e:
            r = classify(e)
        print(f"  {r:10} {p.replace(HOME, '~')}")

    print("\n[exec] interpreters and clients")
    have = [b for b in EXEC_CANDIDATES if shutil.which(b)]
    print(f"  {', '.join(have) or 'none'}")

    print("\n[net] egress")
    reached = set()
    for h, port, path, cat in NET_CANDIDATES:
        try:
            do_http(h, port, path); r = "REACHABLE"; reached.add(h)
        except Exception as e:
            r = classify(e)
        print(f"  {r:10} {h}:{port}{path}")

    # --- verdict -----------------------------------------------------------
    # Every line below rests on a POSITIVE observation. A thing was reached,
    # read, or found present. Negative results are not used, because without
    # a policy "blocked" could be a control or a host that did not answer.
    print("\n" + "=" * 70)
    print("VERDICT")
    print("=" * 70)
    said = False
    egress_open = len(reached) >= 2
    writes_open = len(writable) >= 2
    if egress_open and writes_open:
        print("\n  Nothing is containing this agent. It reached unrelated hosts")
        print("  and wrote outside its working directory.")
        said = True
    else:
        print("\n  Something is containing this agent:")
        if not egress_open:
            print(f"    egress: {len(reached)} of {len(NET_CANDIDATES)} targets reachable")
        if not writes_open:
            print(f"    writes: confined to {len(writable)} of 8 locations tested")
        print("  Note what this does NOT stop: reads. See below.")
        said = True
    creds = [p for p, c in FS_CANDIDATES if c == "secret" and p.startswith(HOME)]
    got = []
    for p in creds:
        try:
            do_read(p); got.append(p.replace(HOME, "~"))
        except Exception:
            pass
    if got:
        print(f"\n  It can read your credentials. {len(got)} reachable:")
        for g in got:
            print(f"    {g}")
        said = True
    if os.environ.get("SSH_AUTH_SOCK") and os.path.exists(os.environ["SSH_AUTH_SOCK"]):
        print("\n  The SSH agent socket is live. It can authenticate as you to")
        print("  every host your keys reach, and sign commits as you, without")
        print("  reading any key file.")
        said = True
    if yours:
        print(f"\n  It inherited {len(yours)} of your own credentials from the")
        print(f"  environment ({', '.join(yours)}), readable by anything it runs.")
        print("  These were already there. The agent did not add them.")
        said = True
    if egress_open:
        print(f"\n  No egress allowlist. It reached {len(reached)} unrelated")
        print("  hosts, so anything above can leave.")
        said = True
    elif got:
        print("\n  It can still READ the credentials above, but egress is")
        print("  filtered, so it cannot send them anywhere. A sandbox limits")
        print("  blast radius; it does not stop an agent reading secrets.")
        said = True
    clients = [b for b in ("ssh", "curl", "wget", "nc", "docker", "git")
               if shutil.which(b)]
    if clients and egress_open:
        print(f"\n  Clients available to do it: {', '.join(clients)}.")
        said = True
    if not said:
        print("\n  Nothing of note reachable.")
    print()

if REPORT_ONLY:
    run_report()
    if OUT: OUT.close()
    raise SystemExit(0)
rc = 1 if run_asserts() else 0
if OUT: OUT.close()
raise SystemExit(rc)
