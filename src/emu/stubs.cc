// Built-in stubs for common C library imports, so a dynamically linked
// program runs without its libraries: process start and exit, output
// (puts, printf), string and memory functions, a bump allocator.
#include "impl.hh"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace revkit::emu {

namespace {

using Handler = Emulator::StubHandler;

std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return (v + a - 1) & ~(a - 1); }

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

bool read_bytes(Emulator &e, std::uint64_t at, std::uint64_t n, std::string &out) {
  out.resize(n);
  return n == 0 || e.read_memory(at, std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(out.data()), n));
}

bool write_bytes(Emulator &e, std::uint64_t at, const std::string &data) {
  return data.empty() ||
         e.write_memory(at, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
}

HookAction fault(StubCall &call, const std::string &what) {
  call.note = call.name + ": " + what;
  return HookAction::stop;
}

// A NUL-terminated string, or nullopt when it runs into unmapped memory.
std::optional<std::string> cstring(Emulator &e, std::uint64_t at, std::size_t max = 1 << 20) {
  std::string out;
  for (std::size_t i = 0; i < max; ++i) {
    std::uint8_t c = 0;
    if (!e.read_memory(at + i, std::span<std::uint8_t>(&c, 1))) return std::nullopt;
    if (c == 0) return out;
    out.push_back(static_cast<char>(c));
  }
  return out;
}

std::int64_t sext32(std::uint64_t v) { return static_cast<std::int32_t>(static_cast<std::uint32_t>(v)); }

// printf's integer and string conversions (%d %i %u %x %X %o %c %s %p %%,
// flags, width, precision and length modifiers). Floating point conversions
// print "<float>": their arguments are in float registers.
std::string format(Emulator &e, const std::string &fmt, unsigned first_arg) {
  std::string out;
  unsigned next = first_arg;
  for (std::size_t i = 0; i < fmt.size(); ++i) {
    if (fmt[i] != '%') {
      out.push_back(fmt[i]);
      continue;
    }
    std::string spec = "%";
    ++i;
    while (i < fmt.size() && std::strchr("-+ #0", fmt[i])) spec.push_back(fmt[i++]);
    while (i < fmt.size() && (std::isdigit(static_cast<unsigned char>(fmt[i])) || fmt[i] == '.')) spec.push_back(fmt[i++]);
    std::string length;
    while (i < fmt.size() && std::strchr("hlzjt", fmt[i])) length.push_back(fmt[i++]);
    if (i >= fmt.size()) break;
    const char conv = fmt[i];
    char buf[128];
    const bool wide = length == "l" || length == "ll" || length == "z" || length == "j" || length == "t";
    switch (conv) {
      case '%': out.push_back('%'); break;
      case 'd':
      case 'i': {
        const std::uint64_t v = e.arg(next++);
        const long long s = wide && e.pointer_size() == 8 ? static_cast<long long>(v) : sext32(v);
        std::snprintf(buf, sizeof buf, (spec + "lld").c_str(), s);
        out += buf;
        break;
      }
      case 'u':
      case 'x':
      case 'X':
      case 'o': {
        std::uint64_t v = e.arg(next++);
        if (!(wide && e.pointer_size() == 8)) v &= 0xffffffffu;
        std::snprintf(buf, sizeof buf, (spec + "ll" + conv).c_str(), static_cast<unsigned long long>(v));
        out += buf;
        break;
      }
      case 'c': out.push_back(static_cast<char>(e.arg(next++))); break;
      case 'p': out += hexs(e.arg(next++)); break;
      case 's': {
        auto s = cstring(e, e.arg(next++));
        std::string text = s ? *s : "(bad)";
        std::snprintf(buf, sizeof buf, (spec + "s").c_str(), "");
        if (spec == "%") out += text;
        else {
          std::vector<char> big(text.size() + 128);
          std::snprintf(big.data(), big.size(), (spec + "s").c_str(), text.c_str());
          out += big.data();
        }
        break;
      }
      case 'f':
      case 'g':
      case 'e':
      case 'a': out += "<float>"; break;
      default: out += spec + conv; break;
    }
  }
  return out;
}

Handler exit_with(std::int64_t fixed, bool use_arg) {
  return [fixed, use_arg](Emulator &e, StubCall &call) {
    call.exited = true;
    call.exit_code = use_arg ? sext32(e.arg(0)) : fixed;
    call.note = call.name + "(" + std::to_string(call.exit_code) + ")";
    return HookAction::proceed;
  };
}

Handler returns(std::uint64_t value) {
  return [value](Emulator &, StubCall &call) {
    call.return_value = value;
    return HookAction::proceed;
  };
}

// Bump allocation from a lazily mapped arena; a block keeps its size in
// the 16 bytes before it, for realloc.
std::optional<std::uint64_t> allocate(Emulator &e, std::uint64_t n) {
  Emulator::Impl &m = e.internals();
  const std::uint64_t need = align_up(std::max<std::uint64_t>(n, 1), 16) + 16;
  if (m.heap_end == 0 || m.heap_next + need > m.heap_end) {
    const std::uint64_t size = std::max<std::uint64_t>(align_up(need, 1 << 20), 16ull << 20);
    auto at = e.find_free(size, m.pointer_size >= 8 ? 0x600000000000ull : 0x30000000ull);
    if (!at) at = e.find_free(size, 0x10000);
    if (!at) return std::nullopt;
    e.map("malloc", *at, size, {true, true, false});
    m.heap_next = *at;
    m.heap_end = *at + size;
  }
  const std::uint64_t block = m.heap_next + 16;
  m.heap_next += need;
  e.write_word(block - 16, 8, n);
  return block;
}

std::optional<Handler> builtin(const std::string &name) {
  if (name == "exit" || name == "_exit" || name == "_Exit" || name == "ExitProcess" || name == "quick_exit")
    return exit_with(0, true);
  if (name == "abort") return exit_with(134, false);
  if (name == "__stack_chk_fail" || name == "__fortify_fail" || name == "__chk_fail")
    return [](Emulator &, StubCall &call) { return fault(call, "stack smashing detected"); };
  if (name == "__cxa_atexit" || name == "atexit" || name == "__cxa_finalize" || name == "__register_atfork" ||
      name == "setvbuf" || name == "fflush" || name == "__libc_csu_init" || name == "__gmon_start__" ||
      name == "_ITM_registerTMCloneTable" || name == "_ITM_deregisterTMCloneTable")
    return returns(0);
  if (name == "free") return [](Emulator &, StubCall &call) { call.returns_value = false; return HookAction::proceed; };
  if (name == "__libc_start_main") {
    // __libc_start_main(main, argc, argv, ...): call main(argc, argv, envp)
    // with a return address that exits with main's result.
    return [](Emulator &e, StubCall &call) {
      Emulator::Impl &m = e.internals();
      const std::uint64_t main = e.arg(0), argc = e.arg(1), argv = e.arg(2);
      if (!m.exit_trap) {
        m.exit_trap = m.alloc_stub("<exit>", nullptr, false);
        m.stubs.erase(*m.exit_trap);
      }
      if (!m.abi.return_register.empty()) {
        e.write_register(m.abi.return_register, *m.exit_trap);
      } else {
        // Reuse the slot holding __libc_start_main's return address, which
        // keeps the stack aligned as main expects.
        const std::uint64_t sp = e.read_register(m.sp_reg.name);
        e.write_word(sp + static_cast<std::uint64_t>(m.abi.return_stack_offset.value_or(0)),
                     m.abi.return_size != 0 ? m.abi.return_size : m.pointer_size, *m.exit_trap);
      }
      const std::uint64_t envp = argv + (argc + 1) * m.pointer_size;
      const std::uint64_t args[] = {argc, argv, envp};
      for (std::size_t i = 0; i < 3 && i < m.abi.int_params.size(); ++i) e.write_register(m.abi.int_params[i], args[i]);
      call.jump_to = main;
      call.note = "__libc_start_main: main(" + std::to_string(argc) + ", " + hexs(argv) + ")";
      return HookAction::proceed;
    };
  }
  if (name == "puts")
    return [](Emulator &e, StubCall &call) {
      auto s = cstring(e, e.arg(0));
      if (!s) return fault(call, "bad string");
      e.internals().out += *s + "\n";
      call.return_value = s->size() + 1;
      return HookAction::proceed;
    };
  if (name == "putchar")
    return [](Emulator &e, StubCall &call) {
      e.internals().out.push_back(static_cast<char>(e.arg(0)));
      call.return_value = e.arg(0) & 0xff;
      return HookAction::proceed;
    };
  if (name == "printf" || name == "__printf_chk")
    return [name](Emulator &e, StubCall &call) {
      const unsigned fmt_arg = name == "printf" ? 0 : 1;
      auto fmt = cstring(e, e.arg(fmt_arg));
      if (!fmt) return fault(call, "bad format");
      const std::string s = format(e, *fmt, fmt_arg + 1);
      e.internals().out += s;
      call.return_value = s.size();
      return HookAction::proceed;
    };
  if (name == "write")
    return [](Emulator &e, StubCall &call) {
      std::string data;
      const std::uint64_t fd = e.arg(0), n = std::min<std::uint64_t>(e.arg(2), 64u << 20);
      if (!read_bytes(e, e.arg(1), n, data)) return fault(call, "bad buffer");
      if (fd == 1) e.internals().out += data;
      else if (fd == 2) e.internals().err += data;
      call.return_value = n;
      return HookAction::proceed;
    };
  if (name == "strlen")
    return [](Emulator &e, StubCall &call) {
      auto s = cstring(e, e.arg(0));
      if (!s) return fault(call, "bad string");
      call.return_value = s->size();
      return HookAction::proceed;
    };
  if (name == "strcmp" || name == "strncmp")
    return [name](Emulator &e, StubCall &call) {
      auto a = cstring(e, e.arg(0)), b = cstring(e, e.arg(1));
      if (!a || !b) return fault(call, "bad string");
      std::string x = *a, y = *b;
      if (name == "strncmp") {
        x = x.substr(0, e.arg(2));
        y = y.substr(0, e.arg(2));
      }
      const int c = std::strcmp(x.c_str(), y.c_str());
      call.return_value = static_cast<std::uint64_t>(static_cast<std::int64_t>(c < 0 ? -1 : c > 0 ? 1 : 0));
      return HookAction::proceed;
    };
  if (name == "strcpy")
    return [](Emulator &e, StubCall &call) {
      auto s = cstring(e, e.arg(1));
      if (!s || !write_bytes(e, e.arg(0), *s + std::string(1, '\0'))) return fault(call, "bad string");
      call.return_value = e.arg(0);
      return HookAction::proceed;
    };
  if (name == "memcpy" || name == "memmove" || name == "__memcpy_chk" || name == "__memmove_chk")
    return [](Emulator &e, StubCall &call) {
      std::string data;
      if (e.arg(2) > (256u << 20) || !read_bytes(e, e.arg(1), e.arg(2), data) || !write_bytes(e, e.arg(0), data))
        return fault(call, "bad buffer");
      call.return_value = e.arg(0);
      return HookAction::proceed;
    };
  if (name == "memset" || name == "__memset_chk")
    return [](Emulator &e, StubCall &call) {
      if (e.arg(2) > (256u << 20) || !write_bytes(e, e.arg(0), std::string(e.arg(2), static_cast<char>(e.arg(1)))))
        return fault(call, "bad buffer");
      call.return_value = e.arg(0);
      return HookAction::proceed;
    };
  if (name == "memcmp")
    return [](Emulator &e, StubCall &call) {
      std::string a, b;
      if (e.arg(2) > (256u << 20) || !read_bytes(e, e.arg(0), e.arg(2), a) || !read_bytes(e, e.arg(1), e.arg(2), b))
        return fault(call, "bad buffer");
      const int c = std::memcmp(a.data(), b.data(), a.size());
      call.return_value = static_cast<std::uint64_t>(static_cast<std::int64_t>(c < 0 ? -1 : c > 0 ? 1 : 0));
      return HookAction::proceed;
    };
  if (name == "malloc" || name == "calloc" || name == "realloc")
    return [name](Emulator &e, StubCall &call) {
      std::uint64_t n = e.arg(name == "realloc" ? 1 : 0);
      if (name == "calloc") n *= e.arg(1);
      if (n > (1ull << 32)) {
        call.return_value = 0;
        return HookAction::proceed;
      }
      auto block = allocate(e, n);
      if (!block) {
        call.return_value = 0;
        return HookAction::proceed;
      }
      if (name == "realloc" && e.arg(0) != 0) {
        const std::uint64_t old = e.read_word(e.arg(0) - 16, 8).value_or(0);
        std::string data;
        if (read_bytes(e, e.arg(0), std::min(old, n), data)) write_bytes(e, *block, data);
      }
      // Fresh mappings are zero-filled, and blocks are never reused.
      call.return_value = *block;
      return HookAction::proceed;
    };
  return std::nullopt;
}

}  // namespace

void install_library_stubs(Emulator::Impl &m) {
  for (const auto &[name, address] : m.import_stubs)
    if (auto h = builtin(name)) m.stubs[address].handler = std::move(*h);
}

}  // namespace revkit::emu
