// rk-sandbox: confines itself and then runs a program (an external
// decompiler) in its place. revkit::providers::run_sandboxed starts it; see
// src/providers/include/revkit/providers/sandbox.h and docs/providers.md.
//
//   rk-sandbox --version | --probe
//   rk-sandbox [--ro PATH]... [--rw PATH]... [--cwd DIR] [--memory BYTES]
//              [--address-space BYTES] [--cpu SECONDS] [--file-size BYTES]
//              [--open-files N] [--weak] -- PROGRAM [ARGS]...
//
// The environment is the program's (the parent passes only what it
// should see). Exit status 125, with "rk-sandbox: ..." on stderr, when the
// helper can't confine itself or start the program.
#include "revkit/providers/sandbox.h"
#include "revkit/runtime/runtime.h"

#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern char **environ;

namespace {

[[noreturn]] void fail(const std::string &why) {
  std::fprintf(stderr, "rk-sandbox: %s\n", why.c_str());
  std::_Exit(125);
}

std::uint64_t number(const char *s) {
  char *end = nullptr;
  errno = 0;
  const unsigned long long v = std::strtoull(s, &end, 10);
  if (errno != 0 || end == s || *end != 0) fail(std::string("not a number: ") + s);
  return v;
}

}  // namespace

int main(int argc, char **argv) {
  using namespace revkit::providers;
  ConfineOptions o;
  int i = 1;
  for (; i < argc; ++i) {
    const std::string a = argv[i];
    auto value = [&]() -> const char * {
      if (i + 1 >= argc) fail(a + " needs a value");
      return argv[++i];
    };
    if (a == "--version") {
      std::printf("%s\n", revkit::runtime::version_string("rk-sandbox").c_str());
      return 0;
    }
    if (a == "--probe") {
      const SandboxSupport s = probe_self();
      std::printf("landlock=%d seccomp=%d netns=%d\n", s.landlock_abi, s.seccomp ? 1 : 0, s.netns ? 1 : 0);
      return 0;
    }
    if (a == "--") {
      ++i;
      break;
    }
    if (a == "--ro") o.read_paths.emplace_back(value());
    else if (a == "--rw") o.write_paths.emplace_back(value());
    else if (a == "--cwd") o.cwd = value();
    else if (a == "--memory") o.memory = number(value());
    else if (a == "--address-space") o.address_space = number(value());
    else if (a == "--cpu") o.cpu = number(value());
    else if (a == "--file-size") o.file_size = number(value());
    else if (a == "--open-files") o.open_files = number(value());
    else if (a == "--weak") o.allow_weak = true;
    else fail("unknown option " + a);
  }
  if (i >= argc) fail("no program to run (usage: rk-sandbox [options] -- PROGRAM [ARGS]...)");
  if (argv[i][0] != '/') fail(std::string("the program must be an absolute path: ") + argv[i]);
  if (std::string e = confine_self(o); !e.empty()) fail(e);
  ::execve(argv[i], argv + i, environ);
  fail(std::string("cannot run ") + argv[i] + ": " + std::strerror(errno));
}
