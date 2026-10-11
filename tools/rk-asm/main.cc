// rk-asm: the SLEIGH assembler from the command line, and the round-trip
// gate's driver (scripts/asm_roundtrip.py).
//
//   rk-asm --lang ARM:LE:32:v4t [--addr 0x20040] [--ctx TMode=1] [--current e280005f] 'bl 0xa0000'
//   rk-asm --lang ARM:LE:32:v4t --complete 'ad'
//   rk-asm --lang ARM:LE:32:v4t --dump              # the grammar
//   rk-asm --roundtrip [--lang L] [--raw [--raw-offset N] [--base B]] [--file-base] BINARY < lines
//
// Round-trip input lines are "address<TAB>length<TAB>text" (what the
// listing shows); for each, the bytes at the address are read from the
// loaded binary, the context is the language default or the first ISA
// variant (ARM TMode, MIPS ISA_MODE) under which those bytes decode to that
// text, and the text is assembled at the address. One JSON object per line
// on stdout: {"a":addr,"s":"exact"|"equivalent"|"failed"|"skipped","us":..,"e":error}.

#include "revkit/asm/assembler.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"
#include "revkit/runtime/runtime.h"

#include "../../src/asm/grammar.hh"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace {

using revkit::assembler::Assembler;

std::uint64_t num(const std::string &s) { return std::stoull(s, nullptr, 0); }

std::vector<std::uint8_t> hex_bytes(const std::string &s) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < s.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
  return out;
}

std::string hex(std::span<const std::uint8_t> b) {
  std::string s;
  char buf[4];
  for (std::uint8_t x : b) {
    std::snprintf(buf, sizeof buf, "%02x", x);
    s += buf;
  }
  return s;
}

std::string json_escape(const std::string &s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') o += '\\';
    if (static_cast<unsigned char>(c) < 0x20) continue;
    o += c;
  }
  return o;
}

int usage() {
  std::cerr << "usage: rk-asm --lang L [--addr A] [--ctx NAME=V]... [--current HEX] TEXT\n"
               "       rk-asm --lang L --complete TEXT | --dump\n"
               "       rk-asm --roundtrip [--lang L] [--raw [--raw-offset N] [--base B]] [--file-base] BINARY < lines\n";
  return 2;
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-asm")) return 0;
  std::string lang, text, ghidra;  // --ghidra; else found by revkit::runtime
  std::uint64_t addr = 0;
  std::vector<std::pair<std::string, std::uint32_t>> ctx;
  std::map<std::string, std::uint64_t, std::less<>> syms;
  std::vector<std::uint8_t> current;
  bool dump = false, complete = false, roundtrip = false, raw = false, file_base = false;
  revkit::loader::RawOptions raw_opts;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto need = [&]() -> std::string {
      if (i + 1 >= argc) std::exit(usage());
      return argv[++i];
    };
    if (a == "--lang") lang = need();
    else if (a == "--ghidra") ghidra = need();
    else if (a == "--addr") addr = num(need());
    else if (a == "--ctx") {
      std::string kv = need();
      auto eq = kv.find('=');
      if (eq == std::string::npos) return usage();
      ctx.emplace_back(kv.substr(0, eq), static_cast<std::uint32_t>(num(kv.substr(eq + 1))));
    } else if (a == "--sym") {
      std::string kv = need();
      auto eq = kv.find('=');
      if (eq == std::string::npos) return usage();
      syms[kv.substr(0, eq)] = num(kv.substr(eq + 1));
    } else if (a == "--current") current = hex_bytes(need());
    else if (a == "--dump") dump = true;
    else if (a == "--complete") complete = true;
    else if (a == "--roundtrip") roundtrip = true;
    else if (a == "--raw") raw = true;
    else if (a == "--raw-offset") raw_opts.offset = num(need());
    else if (a == "--base") {
      raw_opts.base = num(need());
    } else if (a == "--file-base") file_base = true;
    else if (!a.empty() && a[0] == '-' && a.size() > 1 && !std::isdigit(static_cast<unsigned char>(a[1]))) return usage();
    else text = a;
  }
  if (auto root = revkit::runtime::find_ghidra(ghidra, "rk-asm")) ghidra = root->string();
  else return 1;
  try {
    revkit::lift::initialize(ghidra);
    if (roundtrip) {
      if (text.empty()) return usage();
      std::shared_ptr<revkit::loader::Image> image;
      if (raw) {
        if (lang.empty()) return usage();
        raw_opts.language = lang;
        image = std::make_shared<revkit::loader::Image>(revkit::loader::load_raw_file(text, raw_opts));
      } else {
        revkit::loader::LoadOptions lo;
        lo.ghidra_image_base = !file_base;
        image = std::make_shared<revkit::loader::Image>(revkit::loader::load_file(text, lo));
        if (lang.empty()) {
          auto spec = revkit::loader::guess_language(*image);
          if (!spec) throw std::runtime_error("unknown language; pass --lang");
          lang = spec->language;
        }
      }
      Assembler as(lang);
      // Contexts to try: the default, then each ISA switch set.
      std::vector<std::vector<std::uint32_t>> contexts{as.default_context()};
      for (const char *v : {"TMode", "ISA_MODE", "ISAModeSwitch", "vle"}) {
        auto c = as.default_context();
        if (as.set_context(c, v, 1)) contexts.push_back(c);
      }
      std::string line;
      while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string a, l, t;
        if (!std::getline(in, a, '\t') || !std::getline(in, l, '\t') || !std::getline(in, t)) continue;
        if (!t.empty() && t[0] == '_') t.erase(0, 1);  // a delay slot's display prefix
        const std::uint64_t at = num(a);
        const unsigned len = static_cast<unsigned>(num(l));
        std::vector<std::uint8_t> bytes(16);
        image->memory.read(at, std::as_writable_bytes(std::span(bytes)));
        const std::vector<std::uint32_t> *use = nullptr;
        std::size_t which = 0;
        for (std::size_t ci = 0; ci < contexts.size() && !use; ++ci) {
          auto d = as.disassemble(at, bytes, contexts[ci]);
          if (d && d->length == len && Assembler::same_text(d->text, t)) {
            use = &contexts[ci];
            which = ci;
          }
        }
        std::cout << "{\"a\":" << at;
        if (!use) {
          std::cout << ",\"s\":\"skipped\"}\n";
          continue;
        }
        revkit::assembler::Options o;
        std::vector<std::uint8_t> cur(bytes.begin(), bytes.begin() + len);
        o.current = cur;
        auto r = as.assemble(at, t, *use, o);
        std::string status = "failed";
        if (!r.candidates.empty()) status = r.candidates.front().current ? "exact" : "equivalent";
        for (const auto &c : r.candidates)
          if (c.current) status = "exact";
        if (auto mode = as.get_context(*use, "TMode")) std::cout << ",\"m\":" << *mode;
        std::cout << ",\"c\":" << which << ",\"s\":\"" << status << "\",\"us\":" << static_cast<long>(r.micros);
        if (status == "failed") std::cout << ",\"e\":\"" << json_escape(r.error) << "\",\"t\":\"" << json_escape(t) << "\"";
        if (status == "equivalent")
          std::cout << ",\"t\":\"" << json_escape(t) << "\",\"got\":\"" << hex(r.candidates.front().bytes) << "\",\"was\":\""
                    << hex(cur) << "\"";
        std::cout << "}\n";
      }
      return 0;
    }
    if (lang.empty()) return usage();
    Assembler as(lang);
    std::vector<std::uint32_t> c = as.default_context();
    for (const auto &[k, v] : ctx)
      if (!as.set_context(c, k, v)) {
        std::cerr << "rk-asm: unknown context variable " << k << "\n";
        return 1;
      }
    if (dump) {
      if (!text.empty()) {
        // Productions whose description mentions `text`.
        for (const auto &line : as.debug_productions())
          if (line.find(text) != std::string::npos) std::cout << line << "\n";
        return 0;
      }
      auto s = as.stats();
      std::cout << "constructors " << s.constructors << ", productions " << s.productions << ", terminals "
                << s.terminals << ", nonterminals " << s.nonterminals << ", built in " << s.build_ms << " ms\n";
      return 0;
    }
    if (complete) {
      auto r = as.complete(addr, text, text.size(), c);
      std::cout << "from " << r.from << (r.valid_prefix ? "" : " (prefix doesn't parse)") << ":";
      for (const auto &i : r.items) std::cout << " " << i;
      std::cout << "\n";
      return 0;
    }
    if (text.empty() && !current.empty()) {  // disassemble --current
      auto d = as.disassemble(addr, current, c);
      if (!d) {
        std::cout << "doesn't decode\n";
        return 1;
      }
      std::cout << d->text << "  (" << d->length << " bytes)";
      for (const auto &k : d->constructors) std::cout << " " << k;
      std::cout << "\n";
      return 0;
    }
    revkit::assembler::Options o;
    o.current = current;
    o.symbols = [&](std::string_view n) -> std::optional<std::uint64_t> {
      auto it = syms.find(n);
      if (it == syms.end()) return std::nullopt;
      return it->second;
    };
    auto r = as.assemble(addr, text, c, o);
    if (r.candidates.empty()) {
      std::cout << "error: " << r.error;
      if (r.error_column >= 0) std::cout << " (column " << r.error_column << ")";
      std::cout << "\n";
      if (!r.expected.empty()) {
        std::cout << "expected:";
        for (const auto &e : r.expected) std::cout << " " << e;
        std::cout << "\n";
      }
      return 1;
    }
    for (const auto &cand : r.candidates)
      std::cout << hex(cand.bytes) << "  " << cand.text << "  (hamming " << cand.hamming << (cand.current ? ", current" : "")
                << ")\n";
    std::cout << static_cast<long>(r.micros) << " us\n";
  } catch (const std::exception &e) {
    std::cerr << "rk-asm: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
