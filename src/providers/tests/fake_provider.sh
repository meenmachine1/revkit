#!/bin/sh
# A fake external decompiler for the provider tests (providers_test.cc).
# Usage: fake_provider.sh --version | fake_provider.sh INPUT OUTDIR
# The input's first line picks what it does ("mode=ok", "mode=sleep", ...);
# a second line may name a path for the escape checks.
if [ "$1" = "--version" ]; then
  echo "fake-decompiler 1.2.3"
  exit 0
fi
in="$1"
out="$2"
mode=$(sed -n '1s/^mode=//p' "$in")
arg=$(sed -n '2p' "$in")
case "$mode" in
  ok)
    mkdir -p "$out/pkg"
    printf 'class A { int f() { return 1; } }\n' > "$out/pkg/A.java"
    printf 'hello\n' > "$out/notes.txt"
    echo "decompiled" >&2
    ;;
  stdout)
    echo "def f(): return 1"
    ;;
  sleep)
    sleep 60
    ;;
  big)
    head -c 8388608 /dev/zero > "$out/big.bin"
    ;;
  bigstdout)
    head -c 8388608 /dev/zero
    ;;
  many)
    i=0
    while [ $i -lt 400 ]; do : > "$out/f$i"; i=$((i + 1)); done
    sleep 30
    ;;
  manyhome)
    i=0
    while [ $i -lt 400 ]; do : > "$HOME/f$i"; i=$((i + 1)); done
    sleep 30
    ;;
  bigtmp)
    # Five files of 1 MiB each (under the 1 MiB + 1 file size limit) in
    # TMPDIR: more than four times the output cap.
    i=0
    while [ $i -lt 5 ]; do head -c 1048576 /dev/zero > "$TMPDIR/b$i"; i=$((i + 1)); done
    sleep 30
    ;;
  crash)
    kill -SEGV $$
    ;;
  fail)
    echo "cannot decompile this" >&2
    exit 3
    ;;
  oom)
    echo "Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space" >&2
    exit 1
    ;;
  escape)
    # Each line of the report: what was tried, and whether it worked.
    { cat "$arg" >/dev/null 2>&1 && echo "read-outside yes" || echo "read-outside no"
      ls "$(dirname "$arg")" >/dev/null 2>&1 && echo "list-outside yes" || echo "list-outside no"
      (echo x > "$(dirname "$arg")/planted") 2>/dev/null && echo "write-outside yes" || echo "write-outside no"
      (echo x >> "$in") 2>/dev/null && echo "write-input yes" || echo "write-input no"
      cat /etc/hostname >/dev/null 2>&1 && echo "read-etc yes" || echo "read-etc no"
      if command -v python3 >/dev/null; then
        python3 -c 'import socket; socket.create_connection(("127.0.0.1", 9), 2)' >/dev/null 2>&1 && echo "tcp yes" || echo "tcp no"
        python3 -c 'import socket; s = socket.socket(socket.AF_UNIX); s.connect("/run/user/'"$(id -u)"'/bus")' >/dev/null 2>&1 && echo "unix yes" || echo "unix no"
      fi
      kill -0 1 2>/dev/null && echo "signal yes" || echo "signal no"
      # The daemon that started it (bug scrub part 3): its signals, its
      # /proc files, a file's mode outside, and its resource limits.
      kill -0 "$PPID" 2>/dev/null && echo "signal-parent yes" || echo "signal-parent no"
      cat "/proc/$PPID/environ" >/dev/null 2>&1 && echo "proc-parent yes" || echo "proc-parent no"
      # Its own /proc (by pid: the cat below is a child, whose /proc/self
      # isn't the tool's).
      cat "/proc/$$/status" >/dev/null 2>&1 && echo "proc-self yes" || echo "proc-self no"
      chmod 0666 "$arg" 2>/dev/null && echo "chmod-outside yes" || echo "chmod-outside no"
      if command -v python3 >/dev/null; then
        python3 -c 'import sys, resource; resource.prlimit(int(sys.argv[1]), resource.RLIMIT_CORE)' "$PPID" >/dev/null 2>&1 && echo "prlimit-parent yes" || echo "prlimit-parent no"
      fi
      ln -s /etc/passwd "$out/link" 2>/dev/null
      mkfifo "$out/pipe" 2>/dev/null
    } > "$out/report.txt"
    ;;
  linger)
    # A child left behind must die with the run.
    (sleep 1000 & echo $! > "$out/child.pid"; wait) &
    sleep 0.3
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
