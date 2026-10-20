#!/usr/bin/env python3
"""
straceish - human-readable strace

    usage:
        strace -f -tt -T -o trace.txt <commamd> <args>

    parse:
        straceish trace.txt
        straceish < trace.txt
        straceish -v trace.txt            # show boilerplate (futex, fstat, ...)
        straceish --only file,net trace.txt
        straceish --errors-only trace.txt
"""
from __future__ import annotations

import argparse
import os
import re
import signal
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Optional

#  parsing

# optional "[pid 123] " / "123  " prefix (strace -f), optional timestamp (-t/-tt/-ttt/-r)
PREFIX_RE = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d+)\]\s+|(?P<pid2>\d+)\s+(?=\S))?"
    r"(?:(?P<ts>\d+:\d\d:\d\d(?:\.\d+)?|\d+\.\d+)\s+)?"
    r"(?P<body>.*)$"
)
CALL_RE = re.compile(r"^(\w+)\((.*)$")
RESUMED_RE = re.compile(r"^<\.\.\.\s+(\w+)\s+resumed>(.*)$")
RET_RE = re.compile(
    r"^\s*=\s*(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)"
    r"(?:\s+(?P<err>E[A-Z0-9_]+)\s+\((?P<msg>[^)]*)\))?"
)
DUR_RE = re.compile(r"<(\d+\.\d+)>\s*$")
EXIT_RE = re.compile(
    r"^\+\+\+ (?:exited with (?P<code>\d+)|killed by (?P<sig>\w+)(?P<core> \(core dumped\))?) \+\+\+"
)
SIG_RE = re.compile(r"^--- (SIG\w+) ")
LIB_RE = re.compile(r"\.so(\.[\d.]+)*$")


@dataclass
class Call:
    pid: Optional[int]
    ts: Optional[str]
    name: str
    args: list
    ret: str
    err: Optional[str] = None
    errmsg: str = ""
    dur: Optional[float] = None

    @property
    def retval(self) -> Optional[int]:
        return to_int(self.ret)

    @property
    def ok(self) -> bool:
        return self.err is None

    def arg(self, i: int, default: str = "") -> str:
        return self.args[i] if i < len(self.args) else default


@dataclass
class Event:
    cat: str
    base: str
    nbytes: int = 0
    detail: bool = False      # boilerplate: hidden unless -v
    error: bool = False
    expected: bool = False    # failure that is normal (e.g. library path probing)
    slow: bool = False
    count: int = 1
    dur: float = 0.0
    pid: Optional[int] = None
    ts: Optional[str] = None

    def render(self) -> str:
        t = self.base
        if self.nbytes:
            t += f" — {human(self.nbytes)}"
        if self.count > 1:
            t += f" (×{self.count})"
        if self.slow:
            t += f"  🐢 {fmt_dur(self.dur)}"
        return t


def to_int(s: str) -> Optional[int]:
    s = s.strip()
    try:
        return int(s, 0)
    except ValueError:
        m = re.match(r"-?\d+", s)
        return int(m.group()) if m else None


def unq(s: str) -> str:
    """Contents of a leading "quoted" strace string (still escaped)."""
    m = re.match(r'^\s*"((?:[^"\\]|\\.)*)"', s)
    return m.group(1) if m else s.strip()


def short(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def human(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB"):
        if n < 1024:
            return f"{n:.0f} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GiB"


def fmt_dur(s: Optional[float]) -> str:
    if s is None:
        return "?"
    if s < 1e-3:
        return f"{s * 1e6:.0f}µs"
    if s < 1:
        return f"{s * 1e3:.1f}ms"
    return f"{s:.2f}s"


def split_args(s: str):
    """`s` is the text after 'name('. Return (top-level args, text after the closing paren),
    respecting quotes and nested ()[]{} . Returns None if the call isn't closed on this line."""
    args, cur, depth, in_str, i, n = [], [], 0, False, 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(s[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            if depth == 0 and c == ")":
                last = "".join(cur).strip()
                if last or args:
                    args.append(last)
                return args, s[i + 1:]
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    return None


def sockaddr(s: str) -> str:
    m = re.search(r'sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)', s)
    if m:
        return f"{m[2]}:{m[1]}"
    m = re.search(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"', s)
    if m:
        return f"[{m[2]}]:{m[1]}"
    m = re.search(r'sun_path=@?"([^"]*)"', s)
    if m:
        return m[1] or "(abstract socket)"
    m = re.search(r"sa_family=(AF_\w+)", s)
    return m[1] if m else short(s, 40)


#  definition tables

LIB_NAMES = {
    "libc": "C standard library", "libm": "math library", "libpthread": "POSIX threads",
    "libdl": "dynamic loading", "librt": "realtime extensions", "libresolv": "DNS resolver",
    "libstdc++": "C++ standard library", "libgcc_s": "GCC runtime", "libz": "zlib compression",
    "libssl": "OpenSSL (TLS)", "libcrypto": "OpenSSL crypto", "libselinux": "SELinux",
    "libpcre2-8": "PCRE2 regex", "libtinfo": "terminal info", "libncursesw": "ncurses UI",
    "libcap": "Linux capabilities", "libutil": "utility helpers",
}

PATH_HINTS = [  # (regex, category, label)
    (r"/etc/(resolv\.conf|hosts|nsswitch\.conf|host\.conf|gai\.conf)$", "net", "Reading name-resolution config"),
    (r"/etc/(ssl|ca-certificates|pki)/", "net", "Loading TLS certificates"),
    (r"/etc/(passwd|group|shadow)$", "system", "Looking up users/groups"),
    (r"^/(proc|sys)/", "system", "Inspecting kernel info"),
    (r"^/dev/u?random$", "system", "Opening entropy source"),
]

# Syscalls that are mostly boilerplate: hidden unless -v (or unless they fail).
QUIET = {
    "arch_prctl": "Setting up thread-local storage", "set_tid_address": "Registering thread id",
    "set_robust_list": "Registering robust futex list", "rseq": "Registering restartable sequences",
    "prlimit64": "Querying resource limits", "getrlimit": "Querying resource limits",
    "setrlimit": "Setting resource limits", "getrandom": "Fetching random bytes",
    "uname": "Querying kernel version", "getpid": "Querying process id", "gettid": "Querying thread id",
    "getppid": "Querying parent pid", "getuid": "Querying user id", "geteuid": "Querying effective uid",
    "getgid": "Querying group id", "getegid": "Querying effective gid",
    "rt_sigprocmask": "Adjusting signal mask", "sigaltstack": "Setting alternate signal stack",
    "futex": "Futex synchronization", "madvise": "Giving the kernel memory advice",
    "fcntl": "Adjusting fd flags", "ioctl": "Device control (ioctl)", "statfs": "Querying filesystem",
    "sched_getaffinity": "Querying CPU affinity", "sched_yield": "Yielding the CPU",
    "sysinfo": "Querying system info", "clock_gettime": "Reading the clock", "clock_getres": "Reading clock resolution",
    "gettimeofday": "Reading the clock", "time": "Reading the clock", "getcwd": "Querying working directory",
    "epoll_create1": "Creating epoll instance", "epoll_ctl": "Registering fd with epoll",
    "eventfd2": "Creating eventfd", "umask": "Setting umask", "prctl": "Process control (prctl)",
    "membarrier": "Memory barrier", "getsockopt": "Reading socket option", "setsockopt": "Setting socket option",
    "getsockname": "Querying local socket address", "getpeername": "Querying peer address",
    "poll": "Waiting for I/O events", "ppoll": "Waiting for I/O events", "select": "Waiting for I/O events",
    "pselect6": "Waiting for I/O events", "epoll_wait": "Waiting for I/O events",
    "epoll_pwait": "Waiting for I/O events", "munmap": "Unmapping memory", "mprotect": "Changing memory protection",
    "mremap": "Resizing memory mapping", "capget": "Querying capabilities", "setsid": "Creating new session",
    "setpgid": "Setting process group", "getpgrp": "Querying process group",
}

BENIGN_ERRNOS = {"EINPROGRESS", "EAGAIN", "EWOULDBLOCK", "EINTR", "ERESTARTSYS", "ERESTARTNOHAND",
                 "ERESTART_RESTARTBLOCK", "ERESTARTNOINTR"}

SIG_INFO = {
    "SIGSEGV": "invalid memory access (segfault)", "SIGINT": "interrupt (Ctrl-C)",
    "SIGTERM": "termination request", "SIGKILL": "forced kill", "SIGCHLD": "child process changed state",
    "SIGPIPE": "write to a closed pipe/socket", "SIGABRT": "abort()", "SIGALRM": "timer expired",
    "SIGHUP": "hangup", "SIGUSR1": "user signal 1", "SIGUSR2": "user signal 2", "SIGBUS": "bus error",
    "SIGFPE": "arithmetic error", "SIGWINCH": "terminal resized", "SIGILL": "illegal instruction",
}
FATAL_SIGS = {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGABRT", "SIGILL"}

# category -> (icon, tag, ANSI colour)
CATS = {
    "spawn": ("🚀", "Spawn", "35"), "memory": ("🧠", "Memory", "34"), "file": ("📂", "File", "36"),
    "lib": ("📦", "Library", "33"), "loader": ("🔍", "Loader", "33"), "locale": ("🌍", "Locale", "32"),
    "net": ("🌐", "Net", "96"), "proc": ("🧵", "Process", "95"), "signal": ("📡", "Signal", "91"),
    "time": ("⏱", "Time", "37"), "system": ("🖥", "System", "36"), "io": ("🔀", "I/O", "36"),
    "payload": ("✨", "PAYLOAD", "1;92"), "exit": ("🚪", "Exit", "35"),
    "misc": ("·", "Misc", "90"), "other": ("·", "Other", "90"),
}

STD = {0: "stdin", 1: "stdout", 2: "stderr"}
FAMILIES = {"AF_INET6": "IPv6", "AF_INET": "IPv4", "AF_UNIX": "Unix", "AF_LOCAL": "Unix",
            "AF_NETLINK": "netlink", "AF_PACKET": "raw-packet"}

#  handlers

HANDLERS: dict = {}


def handler(*names):
    def deco(fn):
        for n in names:
            HANDLERS[n] = fn
        return fn
    return deco


@handler("execve")
def h_execve(tr, c):
    path = unq(c.arg(0))
    argv = re.findall(r'"((?:[^"\\]|\\.)*)"', c.arg(1))
    tr.spawned.append(path)
    extra = f" — argv: {short(' '.join(argv), 80)}" if argv else ""
    return Event("spawn", f"Executing {path}{extra}")


@handler("openat", "open", "creat", "openat2")
def h_open(tr, c):
    if c.name in ("openat", "openat2"):
        path, flags = unq(c.arg(1)), c.arg(2)
    elif c.name == "creat":
        path, flags = unq(c.arg(0)), "O_WRONLY|O_CREAT|O_TRUNC"
    else:
        path, flags = unq(c.arg(0)), c.arg(1)
    fd = c.retval
    if c.ok and fd is not None and fd >= 0:
        tr.table(c.pid)[fd] = path
    missing = c.err == "ENOENT"
    note = " — not present" if missing else ""

    if re.search(r"ld\.so\.(cache|preload)$", path):
        what = "cache" if "cache" in path else "preload list"
        return Event("loader", f"Checking dynamic-linker {what}{note}", expected=missing)
    if LIB_RE.search(path):
        if c.err:
            return Event("loader", "Probing library search paths (miss)", expected=missing)
        base = os.path.basename(path)
        desc = LIB_NAMES.get(base.split(".so")[0])
        if base not in tr.libs:
            tr.libs.append(base)
        return Event("lib", f"Loading {desc} ({base})" if desc else f"Loading shared library {base}")
    if re.search(r"locale|gconv", path):
        return Event("locale", f"Loading language/character maps ({os.path.basename(path)}){note}",
                     expected=missing)
    for rx, cat, label in PATH_HINTS:
        if re.search(rx, path):
            if c.ok:
                tr.files.add(path)
            return Event(cat, f"{label}: {path}")

    if "O_RDWR" in flags:
        mode = "read+write"
    elif "O_WRONLY" in flags:
        mode = "write"
    elif "O_DIRECTORY" in flags:
        mode = "directory"
    else:
        mode = "read"
    if "O_CREAT" in flags and mode != "directory":
        mode += ", create"
    if c.ok:
        tr.files.add(path)
    return Event("file", f"Opening {path} ({mode})")


@handler("close")
def h_close(tr, c):
    d = tr.desc(c)
    n = to_int(c.arg(0))
    if c.ok and n is not None:
        tr.table(c.pid).pop(n, None)
    return Event("io", f"Closing {d}", detail=True)


@handler("read", "pread64", "readv", "preadv")
def h_read(tr, c):
    d, n = tr.desc(c), c.retval
    got = n if c.ok and n and n > 0 else 0
    tr.bytes_read += got
    ev = Event("io", f"Reading from {d}", nbytes=got)
    if c.ok and n == 0:
        ev.base += " → EOF"
    ev.detail = bool(LIB_RE.search(d))  # reading ELF headers of libraries is noise
    return ev


@handler("write", "pwrite64", "writev", "pwritev")
def h_write(tr, c):
    d, n = tr.desc(c), c.retval
    sent = n if c.ok and n and n > 0 else 0
    tr.bytes_written += sent
    if d in ("stdout", "stderr"):
        if c.name in ("write", "pwrite64"):
            txt = short(unq(c.arg(1)).replace("\\n", "↵"), 70)
            return Event("payload", f'Writing to {d.upper()}: "{txt}"')
        return Event("payload", f"Writing to {d.upper()} (vectored)", nbytes=sent)
    return Event("io", f"Writing to {d}", nbytes=sent)


@handler("mmap", "mmap2")
def h_mmap(tr, c):
    prot, flags, fd = c.arg(2), c.arg(3), to_int(c.arg(4))
    perm = "".join(ch if tag in prot else "-" for ch, tag in (("r", "PROT_READ"), ("w", "PROT_WRITE"), ("x", "PROT_EXEC")))
    if "MAP_ANONYMOUS" in flags:
        what = "anonymous"
    elif fd is not None and fd >= 0:
        what = f"from {tr.table(c.pid).get(fd, f'fd {fd}')}"
    else:
        what = "anonymous"
    return Event("memory", f"Mapping {perm} memory ({what})", nbytes=to_int(c.arg(1)) or 0)


@handler("brk")
def h_brk(tr, c):
    return Event("memory", "Adjusting heap size (brk)")


@handler("clone", "clone3", "fork", "vfork")
def h_clone(tr, c):
    thread = "CLONE_THREAD" in ", ".join(c.args)
    child = c.retval
    if c.ok and child and child > 0:
        tr.table_for_child(c.pid, child, shared=thread)
        tr.children += 0 if thread else 1
    if thread:
        return Event("proc", "Creating a thread")
    return Event("proc", "Creating child process" + (f" → pid {child}" if c.ok and child else ""))


@handler("wait4", "waitid", "waitpid")
def h_wait(tr, c):
    return Event("proc", "Waiting for a child process")


@handler("exit_group")
def h_exit_group(tr, c):
    code = to_int(c.arg(0))
    tr.exit_status = f"code {code}"
    return Event("exit", f"Process exiting with code {code}")


@handler("exit")
def h_exit(tr, c):
    return Event("exit", f"Thread exiting with code {to_int(c.arg(0))}", detail=True)


@handler("rt_sigaction")
def h_sigaction(tr, c):
    return Event("signal", f"Installing handler for {c.arg(0)}", detail=True)


@handler("kill", "tgkill", "tkill")
def h_kill(tr, c):
    sig = c.arg(2) if c.name == "tgkill" else c.arg(1)
    return Event("signal", f"Sending {sig} to pid {c.arg(0)}")


@handler("nanosleep", "clock_nanosleep")
def h_sleep(tr, c):
    m = re.search(r"tv_sec=(\d+), tv_nsec=(\d+)", ", ".join(c.args))
    if not m:
        return Event("time", "Sleeping")
    return Event("time", f"Sleeping for {fmt_dur(int(m[1]) + int(m[2]) / 1e9)}")


# --- path-based and fd-based file operations (table driven) ---
PATH_OPS = {  # name: (path arg index, verb, quiet-when-ok)
    "stat": (0, "Checking", True), "lstat": (0, "Checking", True), "newfstatat": (1, "Checking", True),
    "statx": (1, "Checking", True), "access": (0, "Checking access to", True),
    "faccessat": (1, "Checking access to", True), "faccessat2": (1, "Checking access to", True),
    "readlink": (0, "Reading symlink", True), "readlinkat": (1, "Reading symlink", True),
    "unlink": (0, "Deleting", False), "unlinkat": (1, "Deleting", False),
    "mkdir": (0, "Creating directory", False), "mkdirat": (1, "Creating directory", False),
    "rmdir": (0, "Removing directory", False), "chdir": (0, "Changing directory to", False),
    "chmod": (0, "Changing permissions of", False), "fchmodat": (1, "Changing permissions of", False),
    "chown": (0, "Changing owner of", False), "truncate": (0, "Truncating", False),
}


def h_pathop(tr, c):
    idx, verb, quiet = PATH_OPS[c.name]
    path = unq(c.arg(idx))
    target = path if path else tr.desc(c, 0)  # AT_EMPTY_PATH → the fd itself
    return Event("file", f"{verb} {target}", detail=quiet)


for _n in PATH_OPS:
    HANDLERS[_n] = h_pathop

FD_OPS = {
    "fstat": ("Inspecting", True), "fstat64": ("Inspecting", True), "fstatfs": ("Inspecting filesystem of", True),
    "getdents64": ("Listing directory", False), "getdents": ("Listing directory", False),
    "lseek": ("Seeking in", True), "ftruncate": ("Truncating", False), "fsync": ("Flushing to disk:", False),
    "fdatasync": ("Flushing to disk:", False), "flock": ("Locking", False), "fchmod": ("Changing permissions of", False),
}


def h_fdop(tr, c):
    verb, quiet = FD_OPS[c.name]
    return Event("file", f"{verb} {tr.desc(c)}", detail=quiet)


for _n in FD_OPS:
    HANDLERS[_n] = h_fdop


@handler("rename", "renameat", "renameat2")
def h_rename(tr, c):
    a, b = (0, 1) if c.name == "rename" else (1, 3)
    return Event("file", f"Renaming {unq(c.arg(a))} → {unq(c.arg(b))}")


# --- descriptors ---
@handler("dup", "dup2", "dup3")
def h_dup(tr, c):
    old = tr.desc(c, 0)
    new = c.retval if c.name == "dup" else to_int(c.arg(1))
    if c.ok and new is not None and new >= 0:
        tr.table(c.pid)[new] = old
    return Event("io", f"Duplicating {old} onto {STD.get(new, f'fd {new}')}")


@handler("pipe", "pipe2")
def h_pipe(tr, c):
    m = re.search(r"\[(\d+), (\d+)\]", c.arg(0))
    if m and c.ok:
        t = tr.table(c.pid)
        t[int(m[1])], t[int(m[2])] = "pipe (read end)", "pipe (write end)"
    return Event("io", "Creating a pipe")


# --- networking ---
@handler("socket")
def h_socket(tr, c):
    dom, typ = c.arg(0), c.arg(1)
    fam = next((v for k, v in FAMILIES.items() if k in dom), dom)
    kind = "TCP" if "SOCK_STREAM" in typ else "UDP" if "SOCK_DGRAM" in typ else "raw" if "SOCK_RAW" in typ else ""
    label = " ".join(x for x in (fam, kind, "socket") if x)
    if c.ok and c.retval is not None and c.retval >= 0:
        tr.table(c.pid)[c.retval] = label
    return Event("net", f"Creating {label}")


@handler("connect")
def h_connect(tr, c):
    addr, fd = sockaddr(c.arg(1)), to_int(c.arg(0))
    if fd is not None and (c.ok or c.err == "EINPROGRESS"):
        tr.table(c.pid)[fd] = f"socket → {addr}"
        tr.endpoints.add(addr)
    return Event("net", f"Connecting to {addr}")


@handler("bind")
def h_bind(tr, c):
    return Event("net", f"Binding {tr.desc(c)} to {sockaddr(c.arg(1))}")


@handler("listen")
def h_listen(tr, c):
    return Event("net", f"Listening for connections on {tr.desc(c)}")


@handler("accept", "accept4")
def h_accept(tr, c):
    peer = sockaddr(c.arg(1))
    if c.ok and c.retval is not None and c.retval >= 0:
        tr.table(c.pid)[c.retval] = f"socket ← {peer}"
        return Event("net", f"Accepted connection from {peer}")
    return Event("net", f"Accepting connection on {tr.desc(c)}")


@handler("sendto", "send", "sendmsg", "sendmmsg")
def h_send(tr, c):
    n = c.retval if c.ok and c.retval and c.retval > 0 else 0
    tr.bytes_sent += n
    return Event("net", f"Sending data on {tr.desc(c)}", nbytes=n)


@handler("recvfrom", "recv", "recvmsg", "recvmmsg")
def h_recv(tr, c):
    n = c.retval if c.ok and c.retval and c.retval > 0 else 0
    tr.bytes_recv += n
    return Event("net", f"Receiving data on {tr.desc(c)}", nbytes=n)


@handler("shutdown")
def h_shutdown(tr, c):
    return Event("net", f"Shutting down {tr.desc(c)}")


#  translator

class Translator:
    def __init__(self, slow: float = 0.1):
        self.slow = slow
        self.tables: dict = {}
        self.pending: dict = {}
        # statistics for the summary
        self.calls: Counter = Counter()
        self.cats: Counter = Counter()
        self.errors: Counter = Counter()
        self.time: dict = defaultdict(float)
        self.files: set = set()
        self.libs: list = []
        self.endpoints: set = set()
        self.spawned: list = []
        self.children = 0
        self.bytes_read = self.bytes_written = self.bytes_sent = self.bytes_recv = 0
        self.exit_status: Optional[str] = None
        self.total = 0

    # fd tracking
    def table(self, pid):
        return self.tables.setdefault(pid, dict(STD))

    def table_for_child(self, parent, child, shared):
        self.tables[child] = self.table(parent) if shared else dict(self.table(parent))

    def desc(self, c: Call, i: int = 0) -> str:
        raw = c.arg(i)
        n = to_int(raw)
        return raw if n is None else self.table(c.pid).get(n, f"fd {n}")

    # line → Event
    def feed(self, line: str) -> Optional[Event]:
        line = line.strip()
        if not line:
            return None
        m = PREFIX_RE.match(line)
        pid_s = m["pid1"] or m["pid2"]
        pid, ts, body = (int(pid_s) if pid_s else None), m["ts"], m["body"].strip()

        if body.startswith("+++"):
            ev = self._exit(body)
        elif body.startswith("---"):
            ev = self._signal(body)
        else:
            call = self._parse_call(pid, ts, body)
            if call is None:
                return None
            ev = self._dispatch(call)
        ev.pid, ev.ts = pid, ts
        return ev

    def _parse_call(self, pid, ts, body) -> Optional[Call]:
        rm = RESUMED_RE.match(body)
        if rm:
            name = rm.group(1)
            head = self.pending.pop((pid, name), None)
            if head is None:
                return None
            rest = head + rm.group(2)
        else:
            nm = CALL_RE.match(body)
            if not nm:
                return None
            name, rest = nm.groups()
        if rest.rstrip().endswith("<unfinished ...>"):
            self.pending[(pid, name)] = rest.rstrip()[: -len("<unfinished ...>")]
            return None
        parsed = split_args(rest)
        if not parsed:
            return None
        args, tail = parsed
        rm2 = RET_RE.match(tail)
        if not rm2:
            return None
        dm = DUR_RE.search(tail)
        return Call(pid, ts, name, args, rm2["ret"], rm2["err"], rm2["msg"] or "",
                    float(dm[1]) if dm else None)

    def _dispatch(self, c: Call) -> Event:
        fn = HANDLERS.get(c.name)
        ev = fn(self, c) if fn else None
        if ev is None:
            if c.name in QUIET:
                ev = Event("misc", QUIET[c.name], detail=True)
            else:
                ev = Event("other", f"{c.name}({short(', '.join(c.args), 50)})", detail=True)
        ev.dur = c.dur or 0.0
        if c.err and not ev.expected:
            if c.err in BENIGN_ERRNOS:
                ev.expected = True
                ev.base += f" → {c.err}"
            else:
                ev.error = True
                ev.base += f" → {c.err} ({c.errmsg})"
        if ev.error:
            ev.detail = False
            self.errors[c.err] += 1
        elif c.dur is not None and c.dur >= self.slow:
            ev.detail, ev.slow = False, True
        self.total += 1
        self.calls[c.name] += 1
        self.cats[ev.cat] += 1
        if c.dur:
            self.time[c.name] += c.dur
        return ev

    def _exit(self, body) -> Event:
        m = EXIT_RE.match(body)
        if m and m["code"] is not None:
            self.exit_status = f"code {m['code']}"
            return Event("exit", f"Process exited with code {m['code']}", detail=True)
        if m:
            self.exit_status = f"killed by {m['sig']}"
            return Event("exit", f"Process killed by {m['sig']}{m['core'] or ''}", error=True)
        return Event("exit", "Process finished", detail=True)

    def _signal(self, body) -> Event:
        m = SIG_RE.match(body)
        sig = m[1] if m else "a signal"
        info = SIG_INFO.get(sig)
        return Event("signal", f"Received {sig}" + (f" — {info}" if info else ""),
                     detail=sig in ("SIGCHLD", "SIGWINCH"), error=sig in FATAL_SIGS)


#  output

class Printer:
    def __init__(self, opts, color: bool):
        self.o, self.color = opts, color
        self.cur: Optional[Event] = None
        self.shown = 0
        self.live = sys.stdout.isatty()

    def c(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def visible(self, ev: Event) -> bool:
        if self.o.only and ev.cat not in self.o.only:
            return False
        if self.o.errors_only:
            return ev.error
        return ev.error or self.o.verbose or not ev.detail

    def push(self, ev: Event):
        cur = self.cur
        if (cur and not self.o.no_collapse
                and (cur.pid, cur.cat, cur.base, cur.error) == (ev.pid, ev.cat, ev.base, ev.error)):
            cur.count += 1
            cur.nbytes += ev.nbytes
            cur.dur += ev.dur
            cur.slow = cur.slow or ev.slow
            return
        self.flush()
        self.cur = ev

    def flush(self):
        if self.cur:
            print(self.fmt(self.cur), flush=self.live)
            self.shown += 1
            self.cur = None

    def fmt(self, ev: Event) -> str:
        icon, tag, color = CATS[ev.cat]
        text = ev.render()
        if ev.error:
            icon, color, text = "❌", "31", self.c(text, "31")
        elif ev.expected:
            text = self.c(text, "90")
        parts = []
        if ev.ts and not self.o.no_time:
            parts.append(self.c(ev.ts, "90"))
        if ev.pid is not None:
            parts.append(self.c(f"[{ev.pid}]", "90"))
        parts.append(self.c(f"{icon} {('[' + tag + ']').ljust(10)}", color))
        parts.append(text)
        return " ".join(parts)


def print_summary(tr: Translator, pr: Printer):
    c = pr.c
    hidden = tr.total - pr.shown
    print("\n" + c("─" * 18 + " Summary " + "─" * 18, "1"))
    print(f"Syscalls : {tr.total} total, {pr.shown} lines shown"
          + (f" ({hidden} folded or hidden — see -v, --no-collapse)" if hidden > 0 else ""))
    if tr.cats:
        print("Activity : " + " · ".join(f"{CATS[k][1].lower()} {v}" for k, v in tr.cats.most_common()))
    if tr.spawned:
        print(f"Executed : {', '.join(short(s, 40) for s in tr.spawned[:4])}"
              + (f" (+{len(tr.spawned) - 4} more)" if len(tr.spawned) > 4 else ""))
    if tr.children:
        print(f"Children : {tr.children} child process(es) created")
    if tr.libs:
        print(f"Libraries: {', '.join(tr.libs[:6])}" + (f" (+{len(tr.libs) - 6} more)" if len(tr.libs) > 6 else ""))
    if tr.files:
        shown = sorted(tr.files)[:6]
        print(f"Files    : {len(tr.files)} opened — {', '.join(short(f, 36) for f in shown)}"
              + (" …" if len(tr.files) > 6 else ""))
    if tr.endpoints:
        print(f"Network  : {', '.join(sorted(tr.endpoints))}")
    io = []
    for label, n in (("read", tr.bytes_read), ("wrote", tr.bytes_written),
                     ("sent", tr.bytes_sent), ("received", tr.bytes_recv)):
        if n:
            io.append(f"{label} {human(n)}")
    if io:
        print("I/O      : " + ", ".join(io))
    if tr.errors:
        errs = ", ".join(f"{k} ×{v}" for k, v in tr.errors.most_common(5))
        print(c(f"Errors   : {sum(tr.errors.values())} failed call(s) — {errs}", "31"))
    if tr.time:
        top = sorted(tr.time.items(), key=lambda kv: -kv[1])[:3]
        print("Slowest  : " + ", ".join(f"{k} {fmt_dur(v)}" for k, v in top))
    if tr.exit_status:
        print(f"Exit     : {tr.exit_status}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Translate strace output into readable context.")
    ap.add_argument("files", nargs="*", help="strace output files (default: stdin)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show boilerplate syscalls")
    ap.add_argument("--only", type=lambda s: set(s.split(",")), default=set(),
                    help="comma-separated categories: " + ",".join(CATS))
    ap.add_argument("-e", "--errors-only", action="store_true", help="show only failed calls")
    ap.add_argument("--no-collapse", action="store_true", help="don't merge repeated lines")
    ap.add_argument("--no-summary", action="store_true", help="skip the closing summary")
    ap.add_argument("--no-time", action="store_true", help="hide strace timestamps")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("--slow", type=float, default=0.1, metavar="SEC",
                    help="flag calls slower than this when -T was used (default 0.1)")
    opts = ap.parse_args(argv)

    color = sys.stdout.isatty() and not opts.no_color and "NO_COLOR" not in os.environ
    tr, pr = Translator(opts.slow), Printer(opts, color)

    def stream():
        if opts.files:
            for path in opts.files:
                with open(path, errors="replace") as fh:
                    yield from fh
        else:
            yield from sys.stdin

    for line in stream():
        ev = tr.feed(line)
        if ev and pr.visible(ev):
            pr.push(ev)
    pr.flush()

    if tr.total == 0:
        print("No syscalls parsed. Remember strace writes to stderr: use `strace -o trace.txt ...`\n"
              "or `strace ... 2>&1 >/dev/null | straceish`.", file=sys.stderr)
        return 1
    if not opts.no_summary:
        print_summary(tr, pr)
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
