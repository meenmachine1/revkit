#include "revkit/decompd/runner.h"

#include "revkit/decompd/lift_mode.h"
#include "revkit/decompd/param_id.h"
#include "revkit/decompd/signature.h"

#include "error.hh"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <new>

#include <malloc.h>
#include <unistd.h>

namespace revkit::decompd {

namespace {

std::mutex &registry_mu() {
  static std::mutex m;
  return m;
}
struct Registered {
  SessionFactory factory;
  PayloadPrinter printer;
};
std::map<Mode, Registered> &registry() {
  static std::map<Mode, Registered> r = [] {
    std::map<Mode, Registered> m;
    m[Mode::c_text] = {[](const Bundle &b) { return make_lift_session(b); },
                       [](std::string_view payload, bool &ok) {
                         lift::DecompileResult r = decode_result(payload);
                         ok = r.ok;
                         return r.ok ? r.c : "/* decompilation failed: " + r.error + " */\n";
                       }};
    m[Mode::param_id] = {[](const Bundle &b) { return make_param_id_session(b); }, print_signature};
    m[Mode::signature] = {[](const Bundle &b) { return make_signature_session(b); }, print_function_signature};
    return m;
  }();
  return r;
}

// Sessions kept per runner: a worker serving two programs (or two modes)
// alternately keeps both.
constexpr std::size_t kSessions = 2;
// Anonymous memory past which a run's end trims malloc's free memory.
constexpr std::uint64_t kTrimAbove = std::uint64_t{160} << 20;

}  // namespace

void register_mode(Mode mode, SessionFactory factory, PayloadPrinter printer) {
  std::lock_guard lock(registry_mu());
  registry()[mode] = {std::move(factory), std::move(printer)};
}

std::string print_payload(Mode mode, std::string_view payload, bool &ok) {
  PayloadPrinter p;
  {
    std::lock_guard lock(registry_mu());
    if (auto it = registry().find(mode); it != registry().end()) p = it->second.printer;
  }
  ok = false;
  if (!p) return std::string("(no printer for mode ") + mode_name(mode) + ")\n";
  return p(payload, ok);
}

bool mode_registered(Mode mode) {
  std::lock_guard lock(registry_mu());
  return registry().contains(mode);
}

std::pair<std::uint64_t, std::uint64_t> resident_memory() {
  std::ifstream statm("/proc/self/statm");
  std::uint64_t size = 0, resident = 0, shared = 0;
  statm >> size >> resident >> shared;
  const auto page = static_cast<std::uint64_t>(sysconf(_SC_PAGESIZE));
  return {resident * page, (resident > shared ? resident - shared : 0) * page};
}

std::shared_ptr<const loader::Image> bundle_image(const Bundle &b) {
  auto image = std::make_shared<loader::Image>();
  image->format = b.format;
  image->bits = b.bits;
  image->blocks = b.image_blocks;
  image->file = std::make_shared<loader::Bytes>();
  image->memory = loader::Memory(image->file);
  return image;
}

std::size_t BundleMemory::read(std::uint64_t addr, std::span<std::uint8_t> out) {
  std::size_t mapped = 0;
  bool missing = false;
  for (std::size_t i = 0; i < out.size(); ++i) {
    const std::uint64_t a = addr + i;
    out[i] = 0;
    if (bundle_ == nullptr || !bundle_->mapped_at(a)) continue;
    ++mapped;
    auto it = bundle_->chunks.find(a / kChunk);
    if (it == bundle_->chunks.end()) {
      missed_.insert(a / kChunk);
      missing = true;
      continue;
    }
    out[i] = static_cast<std::uint8_t>(it->second[a % kChunk]);
  }
  // Bytes the bundle lacks read as no data at all (the decompiler stops
  // there, as at unreadable memory), never as made-up bytes it would follow:
  // the parent adds them and the run is repeated.
  return missing ? 0 : mapped;
}

Runner::Entry Runner::build(const Bundle &b) {
  SessionFactory factory;
  {
    std::lock_guard lock(registry_mu());
    auto it = registry().find(b.mode);
    if (it == registry().end()) throw std::runtime_error(std::string("no decompiler for mode ") + mode_name(b.mode));
    factory = it->second.factory;
  }
  Entry e;
  e.key = b.arch_key();
  e.session = factory(b);
  // The records the architecture starts with (its compiler spec's) are
  // not part of any bundle's joins.
  e.session->architecture().joins_from(e.next_join);
  return e;
}

Runner::Entry &Runner::session_for(const Bundle &b) {
  const std::string key = b.arch_key();
  for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
    if (it->key != key) continue;
    if (it->session->spoiled()) {
      sessions_.erase(it);
      break;
    }
    sessions_.splice(sessions_.begin(), sessions_, it);
    return sessions_.front();
  }
  sessions_.push_front(build(b));
  while (sessions_.size() > kSessions) sessions_.pop_back();
  return sessions_.front();
}

void Runner::warm(const Bundle &b) { session_for(b); }

RunResult Runner::run(std::string_view bytes, const Limits &limits) {
  Bundle b;
  try {
    b = decode_bundle(bytes);
  } catch (const std::exception &e) {
    RunResult r;
    r.error = std::string("bad bundle: ") + e.what();
    return r;
  }
  return run(b, limits);
}

namespace {

// Fault injection for tests of the failure path (never set in use):
// REVKIT_DECOMPD_FAULT=<kind>@<entry in hex>, kind segv, fpe, abort, hang
// or oom, makes a worker fail that way when it decompiles that function;
// sleep<ms> delays it that long first (a run its deadline kills, which a
// longer one survives).
void inject_fault(std::uint64_t entry) {
  static const std::string spec = [] {
    const char *e = std::getenv("REVKIT_DECOMPD_FAULT");
    return std::string(e != nullptr ? e : "");
  }();
  if (spec.empty()) return;
  const auto at = spec.find('@');
  if (at == std::string::npos || std::strtoull(spec.c_str() + at + 1, nullptr, 16) != entry) return;
  const std::string kind = spec.substr(0, at);
  if (kind == "segv") std::raise(SIGSEGV);
  if (kind == "fpe") std::raise(SIGFPE);
  if (kind == "abort") std::abort();
  if (kind == "hang")
    for (;;) ::pause();
  if (kind == "oom") throw std::bad_alloc();
  if (kind.starts_with("sleep"))  // through the worker's watchdog signals
    std::this_thread::sleep_for(std::chrono::milliseconds(std::strtoul(kind.c_str() + 5, nullptr, 10)));
}

}  // namespace

RunResult Runner::run(const Bundle &b, const Limits &limits) {
  const auto started = std::chrono::steady_clock::now();
  inject_fault(b.entry);
  RunResult r;
  try {
    Entry *e = &session_for(b);
    if (b.joins) {
      // Lay out exactly the records the bundle names: what this session
      // has made must be a prefix of them, else start afresh.
      const std::vector<lift::JoinFacts> &want = *b.joins;
      const bool prefix = e->joins.size() <= want.size() && std::equal(e->joins.begin(), e->joins.end(), want.begin());
      if (!prefix) {
        sessions_.erase(sessions_.begin());
        sessions_.push_front(build(b));
        e = &sessions_.front();
      }
      for (std::size_t i = e->joins.size(); i < want.size(); ++i) e->session->architecture().add_join(want[i]);
      std::vector<lift::JoinFacts> laid = e->session->architecture().joins_from(e->next_join);
      e->joins.insert(e->joins.end(), laid.begin(), laid.end());
      if (e->joins != want) throw std::runtime_error("join records could not be laid out as the bundle names them");
    }
    e->session->architecture().flush_decode_cache();
    e->session->run(b, limits, r);
    r.ran = true;
    std::vector<lift::JoinFacts> made = e->session->architecture().joins_from(e->next_join);
    if (b.joins) r.joins_made = made;
    e->joins.insert(e->joins.end(), made.begin(), made.end());
    std::sort(r.misses.begin(), r.misses.end());
    r.misses.erase(std::unique(r.misses.begin(), r.misses.end()), r.misses.end());
    // Answers the decompiler guessed leave nothing behind that matters:
    // the decode cache is flushed before every run, and join records are
    // laid out per bundle when they matter (Bundle::joins).
    if (e->session->spoiled()) sessions_.erase(sessions_.begin());
  } catch (const ghidra::LowlevelError &err) {
    r.ran = false;
    r.error = err.explain;
    sessions_.clear();
  } catch (const std::bad_alloc &) {
    throw;  // the worker reports it as out of memory
  } catch (const std::exception &err) {
    r.ran = false;
    r.error = err.what();
    sessions_.clear();
  }
  r.milliseconds = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  std::tie(r.rss, r.rss_anon) = resident_memory();
  // malloc keeps what a large run freed; give it back now rather than have
  // the pool count it (and replace the worker) later.
  if (r.rss_anon > kTrimAbove) {
    ::malloc_trim(0);
    std::tie(r.rss, r.rss_anon) = resident_memory();
  }
  return r;
}

}  // namespace revkit::decompd
