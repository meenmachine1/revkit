#include "revkit/plugins/host.h"

#include "guest_copy.h"

#include "revkit/facts/fingerprint.h"

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#ifdef REVKIT_HAVE_WASMTIME
#include <wasmtime.h>
#endif


namespace revkit::plugins {

std::string_view to_string(Failure f) {
  switch (f) {
    case Failure::none: return "ok";
    case Failure::plugin_error: return "plugin error";
    case Failure::trap: return "trap";
    case Failure::out_of_fuel: return "out of fuel";
    case Failure::out_of_memory: return "out of memory";
    case Failure::timeout: return "timeout";
    case Failure::bad_output: return "bad output";
  }
  return "?";
}

// ---- process-wide index of loaded modules -----------------------------------

namespace {

std::mutex &registry_mu() {
  static std::mutex mu;
  return mu;
}
std::map<std::string, std::weak_ptr<const Plugin>> &registry() {
  static std::map<std::string, std::weak_ptr<const Plugin>> r;
  return r;
}

void register_plugin(const std::shared_ptr<const Plugin> &p) {
  std::lock_guard lock(registry_mu());
  auto &r = registry();
  for (auto it = r.begin(); it != r.end();) it = it->second.expired() ? r.erase(it) : std::next(it);
  r[p->fingerprint()] = p;
}

std::string read_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + path.string());
  std::stringstream s;
  s << in.rdbuf();
  return s.str();
}

constexpr std::size_t kMaxLogLines = 200;
constexpr std::size_t kMaxLogLine = 1024;
constexpr std::size_t kMaxOutput = 64u << 20;
constexpr std::size_t kMaxRead = 16u << 20;  // per memory_read/file_read call
constexpr std::size_t kMaxError = 2048;

}  // namespace

std::shared_ptr<const Plugin> find_by_fingerprint(const std::string &fingerprint) {
  std::lock_guard lock(registry_mu());
  auto it = registry().find(fingerprint);
  return it == registry().end() ? nullptr : it->second.lock();
}

// ---- the runtime -------------------------------------------------------------

#ifdef REVKIT_HAVE_WASMTIME

namespace detail {

// One wasmtime engine for the host, with a thread that advances its epoch
// for the wall-clock backstop.
struct Runtime {
  static constexpr std::chrono::milliseconds kTick{10};

  wasm_engine_t *engine = nullptr;
  std::mutex mu;
  std::condition_variable cv;
  bool stop = false;
  std::thread ticker;

  Runtime() {
    wasm_config_t *config = wasm_config_new();
    wasmtime_config_consume_fuel_set(config, true);
    wasmtime_config_epoch_interruption_set(config, true);
    // Determinism: one canonical NaN, no threads or shared memory, no
    // relaxed SIMD (its results differ between CPUs).
    wasmtime_config_cranelift_nan_canonicalization_set(config, true);
    wasmtime_config_wasm_threads_set(config, false);
    wasmtime_config_shared_memory_set(config, false);
    wasmtime_config_wasm_relaxed_simd_set(config, false);
    wasmtime_config_wasm_memory64_set(config, false);
    wasmtime_config_wasm_multi_memory_set(config, false);
    wasmtime_config_wasm_gc_set(config, false);
    wasmtime_config_wasm_component_model_set(config, false);
    // Explicit bounds and stack checks instead of a process-wide SIGSEGV
    // handler: the daemon hosts gRPC and Ghidra too, and sanitizers own
    // the signal handlers in their builds.
    wasmtime_config_signals_based_traps_set(config, false);
    wasmtime_config_memory_reservation_set(config, 0);
    wasmtime_config_memory_guard_size_set(config, 0);
    wasmtime_config_memory_reservation_for_growth_set(config, 1u << 20);
    // Compile on the calling thread; no thread pool inside the library.
    wasmtime_config_parallel_compilation_set(config, false);
    wasmtime_config_max_wasm_stack_set(config, 512u << 10);
    engine = wasm_engine_new_with_config(config);
    if (!engine) throw std::runtime_error("cannot create the wasmtime engine");
    ticker = std::thread([this] {
      std::unique_lock lock(mu);
      while (!cv.wait_for(lock, kTick, [this] { return stop; })) wasmtime_engine_increment_epoch(engine);
    });
  }
  ~Runtime() {
    {
      std::lock_guard lock(mu);
      stop = true;
    }
    cv.notify_all();
    ticker.join();
    wasm_engine_delete(engine);
  }
};

struct Compiled {
  std::shared_ptr<Runtime> runtime;  // destroyed last
  wasmtime_module_t *module = nullptr;
  wasmtime_linker_t *linker = nullptr;
  wasmtime_instance_pre_t *pre = nullptr;

  ~Compiled() {
    if (pre) wasmtime_instance_pre_delete(pre);
    if (linker) wasmtime_linker_delete(linker);
    if (module) wasmtime_module_delete(module);
  }
};

}  // namespace detail

namespace {

std::string message_of(wasmtime_error_t *err) {
  wasm_byte_vec_t m;
  wasmtime_error_message(err, &m);
  std::string s(m.data, m.size);
  wasm_byte_vec_delete(&m);
  wasmtime_error_delete(err);
  return s;
}

std::string message_of(wasm_trap_t *trap) {
  wasm_byte_vec_t m;
  wasm_trap_message(trap, &m);
  std::string s(m.data, m.size);
  wasm_byte_vec_delete(&m);
  return s;
}

std::string clip(std::string s, std::size_t n = kMaxError) {
  if (s.size() > n) {
    s.resize(n);
    s += "...";
  }
  return s;
}

// ---- host imports ----------------------------------------------------------

enum class Import : std::uintptr_t {
  log,
  fail,
  set_output,
  take,
  program_info,
  memory_read,
  file_size,
  file_read,
  functions,
  function_code,
  symbol_name,
  now,
  schedule,
  irq_set,
  output,
  bus_read,
  bus_write,
};

struct ImportSpec {
  std::string_view name;
  Import id;
  bool needs_facts;  // not for loaders
  std::optional<Capability> capability;
  std::vector<wasm_valkind_t> params;
  std::vector<wasm_valkind_t> results;
  bool peripheral = false;  // only for peripherals
};

const std::vector<ImportSpec> &import_specs() {
  static const std::vector<ImportSpec> specs = {
      {"log", Import::log, false, std::nullopt, {WASM_I32, WASM_I32}, {}},
      {"fail", Import::fail, false, std::nullopt, {WASM_I32, WASM_I32}, {}},
      {"set_output", Import::set_output, false, std::nullopt, {WASM_I32, WASM_I32}, {}},
      {"take", Import::take, true, std::nullopt, {WASM_I32}, {WASM_I32}},
      {"program_info", Import::program_info, true, std::nullopt, {}, {WASM_I32}},
      {"memory_read", Import::memory_read, true, Capability::memory, {WASM_I64, WASM_I32, WASM_I32}, {WASM_I32}},
      {"file_size", Import::file_size, true, Capability::file, {}, {WASM_I64}},
      {"file_read", Import::file_read, true, Capability::file, {WASM_I64, WASM_I32, WASM_I32}, {WASM_I32}},
      {"functions", Import::functions, true, Capability::code, {}, {WASM_I32}},
      {"function_code", Import::function_code, true, Capability::code, {WASM_I64}, {WASM_I32}},
      {"symbol_name", Import::symbol_name, true, Capability::code, {WASM_I64}, {WASM_I32}},
      {"now", Import::now, false, std::nullopt, {}, {WASM_I64}, true},
      {"schedule", Import::schedule, false, std::nullopt, {WASM_I64}, {}, true},
      {"irq_set", Import::irq_set, false, Capability::irq, {WASM_I32, WASM_I32}, {}, true},
      {"output", Import::output, false, Capability::output, {WASM_I32, WASM_I32}, {}, true},
      {"bus_read", Import::bus_read, false, Capability::bus, {WASM_I64, WASM_I32, WASM_I32}, {WASM_I32}, true},
      {"bus_write", Import::bus_write, false, Capability::bus, {WASM_I64, WASM_I32, WASM_I32}, {WASM_I32}, true},
  };
  return specs;
}

const ImportSpec *find_import(std::string_view name) {
  for (const ImportSpec &s : import_specs())
    if (s.name == name) return &s;
  return nullptr;
}

// Per-call state, reached from host imports through the store's data.
struct CallState {
  FactProvider *facts = nullptr;
  PeripheralHost *periph = nullptr;  // peripherals
  std::string staged;
  std::string output;
  bool has_output = false;
  std::vector<std::string> log;
  std::exception_ptr error;   // thrown by `facts`, rethrown after the call
  bool host_out_of_fuel = false;
  std::optional<std::string> failed;  // fail()'s message
};

struct HostTrap {
  std::string message;
};

// The guest's linear memory, as seen from a host import.
struct GuestMemory {
  std::uint8_t *data = nullptr;
  std::size_t size = 0;

  explicit GuestMemory(wasmtime_caller_t *caller) {
    wasmtime_extern_t item;
    if (!wasmtime_caller_export_get(caller, abi::kExportMemory.data(), abi::kExportMemory.size(), &item) ||
        item.kind != WASMTIME_EXTERN_MEMORY)
      throw HostTrap{"the plugin exports no memory"};
    wasmtime_context_t *cx = wasmtime_caller_context(caller);
    data = wasmtime_memory_data(cx, &item.of.memory);
    size = wasmtime_memory_data_size(cx, &item.of.memory);
    wasmtime_extern_delete(&item);
  }
  // A guest buffer, bounds-checked: a plugin can't make the host touch
  // memory outside its own.
  std::span<std::uint8_t> span(std::int32_t ptr, std::int32_t len) const {
    auto p = static_cast<std::uint32_t>(ptr), n = static_cast<std::uint32_t>(len);
    if (len < 0 || std::uint64_t(p) + n > size) throw HostTrap{"buffer outside the plugin's memory"};
    return {data + p, n};
  }
};

// Host work costs fuel too, so a plugin can't spin on imports for free.
void charge(wasmtime_context_t *cx, CallState &st, std::uint64_t cost) {
  std::uint64_t fuel = 0;
  wasmtime_context_get_fuel(cx, &fuel);
  if (fuel < cost) {
    wasmtime_context_set_fuel(cx, 0);
    st.host_out_of_fuel = true;
    throw HostTrap{"all fuel consumed by host calls"};
  }
  if (auto *err = wasmtime_context_set_fuel(cx, fuel - cost)) message_of(err);
}

std::int32_t stage(CallState &st, std::optional<std::string> blob) {
  if (!blob) {
    st.staged.clear();
    return abi::kNotFound;
  }
  if (blob->size() > static_cast<std::size_t>(INT32_MAX)) throw HostTrap{"fact blob too large"};
  st.staged = std::move(*blob);
  return static_cast<std::int32_t>(st.staged.size());
}

wasm_trap_t *dispatch(void *env, wasmtime_caller_t *caller, const wasmtime_val_t *args, size_t, wasmtime_val_t *results,
                      size_t) {
  const auto id = static_cast<Import>(reinterpret_cast<std::uintptr_t>(env));
  wasmtime_context_t *cx = wasmtime_caller_context(caller);
  auto &st = *static_cast<CallState *>(wasmtime_context_get_data(cx));
  try {
    constexpr std::uint64_t kCallCost = 1000;
    auto i32 = [&](std::size_t i) { return args[i].of.i32; };
    auto u64 = [&](std::size_t i) { return static_cast<std::uint64_t>(args[i].of.i64); };
    auto ret32 = [&](std::int32_t v) {
      results[0].kind = WASMTIME_I32;
      results[0].of.i32 = v;
    };
    auto per_byte = [](std::size_t n) { return n / 8; };
    charge(cx, st, kCallCost);
    switch (id) {
      case Import::log: {
        GuestMemory mem(caller);
        auto s = mem.span(i32(0), i32(1));
        charge(cx, st, per_byte(s.size()));
        if (st.log.size() < kMaxLogLines) st.log.push_back(detail::guest_string(s.data(), std::min(s.size(), kMaxLogLine)));
        return nullptr;
      }
      case Import::fail: {
        GuestMemory mem(caller);
        auto s = mem.span(i32(0), std::min(i32(1), static_cast<std::int32_t>(kMaxError)));
        st.failed = detail::guest_string(s.data(), s.size());
        throw HostTrap{"the plugin failed: " + *st.failed};
      }
      case Import::set_output: {
        GuestMemory mem(caller);
        auto s = mem.span(i32(0), i32(1));
        if (s.size() > kMaxOutput) throw HostTrap{"output larger than 64 MiB"};
        charge(cx, st, per_byte(s.size()));
        st.output = detail::guest_string(s.data(), s.size());
        st.has_output = true;
        return nullptr;
      }
      case Import::take: {
        GuestMemory mem(caller);
        auto dst = mem.span(i32(0), static_cast<std::int32_t>(st.staged.size()));
        detail::guest_write(dst.data(), st.staged.data(), st.staged.size());
        ret32(static_cast<std::int32_t>(st.staged.size()));
        st.staged.clear();
        return nullptr;
      }
      case Import::program_info: {
        std::int32_t n = stage(st, st.facts->program_info());
        charge(cx, st, per_byte(st.staged.size()));
        ret32(n);
        return nullptr;
      }
      case Import::memory_read:
      case Import::file_read: {
        GuestMemory mem(caller);
        auto dst = mem.span(i32(1), i32(2));
        if (dst.size() > kMaxRead) throw HostTrap{"reads are limited to 16 MiB per call"};
        charge(cx, st, per_byte(dst.size()));
        std::span<std::byte> out(reinterpret_cast<std::byte *>(dst.data()), dst.size());
        // The provider may read the store: copy through a buffer, so a
        // throw can't leave guest memory half-written in a way that matters.
        std::vector<std::byte> buf(out.size());
        std::size_t n = id == Import::memory_read ? st.facts->memory_read(u64(0), buf)
                                                  : st.facts->file_read(u64(0), buf);
        GuestMemory again(caller);  // the provider can't grow guest memory, but be safe
        auto target = again.span(i32(1), i32(2));
        detail::guest_write(target.data(), buf.data(), n);
        ret32(static_cast<std::int32_t>(n));
        return nullptr;
      }
      case Import::file_size:
        results[0].kind = WASMTIME_I64;
        results[0].of.i64 = static_cast<std::int64_t>(st.facts->file_size());
        return nullptr;
      case Import::functions: {
        std::int32_t n = stage(st, st.facts->functions());
        charge(cx, st, per_byte(st.staged.size()));
        ret32(n);
        return nullptr;
      }
      case Import::function_code: {
        std::int32_t n = stage(st, st.facts->function_code(u64(0)));
        charge(cx, st, per_byte(st.staged.size()));
        ret32(n);
        return nullptr;
      }
      case Import::symbol_name: {
        std::int32_t n = stage(st, st.facts->symbol_name(u64(0)));
        ret32(n);
        return nullptr;
      }
      case Import::now:
        results[0].kind = WASMTIME_I64;
        results[0].of.i64 = static_cast<std::int64_t>(st.periph->now());
        return nullptr;
      case Import::schedule:
        st.periph->schedule(args[0].of.i64);
        return nullptr;
      case Import::irq_set:
        st.periph->irq(static_cast<std::uint32_t>(i32(0)), i32(1) != 0);
        return nullptr;
      case Import::output: {
        GuestMemory mem(caller);
        auto s = mem.span(i32(0), i32(1));
        if (s.size() > (1u << 20)) throw HostTrap{"output is limited to 1 MiB per call"};
        charge(cx, st, per_byte(s.size()));
        st.periph->output(detail::guest_string(s.data(), s.size()));
        return nullptr;
      }
      case Import::bus_read:
      case Import::bus_write: {
        GuestMemory mem(caller);
        auto buf = mem.span(i32(1), i32(2));
        if (buf.size() > (1u << 20)) throw HostTrap{"bus transfers are limited to 1 MiB per call"};
        charge(cx, st, per_byte(buf.size()));
        std::vector<std::uint8_t> tmp(buf.size());
        bool ok = false;
        if (id == Import::bus_read) {
          ok = st.periph->bus_read(u64(0), tmp);
          GuestMemory again(caller);
          auto target = again.span(i32(1), i32(2));
          if (ok) detail::guest_write(target.data(), tmp.data(), tmp.size());
        } else {
          const std::string bytes = detail::guest_string(buf.data(), buf.size());
          ok = st.periph->bus_write(u64(0), std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()));
        }
        ret32(ok ? static_cast<std::int32_t>(buf.size()) : -1);
        return nullptr;
      }
    }
    throw HostTrap{"unknown import"};
  } catch (const HostTrap &t) {
    if (st.host_out_of_fuel) return wasmtime_trap_new_code(WASMTIME_TRAP_CODE_OUT_OF_FUEL);
    return wasmtime_trap_new(t.message.data(), t.message.size());
  } catch (...) {
    // A fact read failed (or a query cycle unwound): stop the plugin and
    // hand the exception to the caller once the wasm frames are gone.
    st.error = std::current_exception();
    static constexpr std::string_view kMsg = "host error";
    return wasmtime_trap_new(kMsg.data(), kMsg.size());
  }
}

wasm_functype_t *functype(const std::vector<wasm_valkind_t> &params, const std::vector<wasm_valkind_t> &results) {
  wasm_valtype_vec_t p, r;
  std::vector<wasm_valtype_t *> pv, rv;
  for (auto k : params) pv.push_back(wasm_valtype_new(k));
  for (auto k : results) rv.push_back(wasm_valtype_new(k));
  if (pv.empty()) wasm_valtype_vec_new_empty(&p);
  else wasm_valtype_vec_new(&p, pv.size(), pv.data());
  if (rv.empty()) wasm_valtype_vec_new_empty(&r);
  else wasm_valtype_vec_new(&r, rv.size(), rv.data());
  return wasm_functype_new(&p, &r);
}

struct Store {
  wasmtime_store_t *store;
  wasmtime_context_t *cx;
  Store(wasm_engine_t *engine, CallState *state, const Limits &limits) {
    store = wasmtime_store_new(engine, state, nullptr);
    // Linear memory is capped; one memory, a handful of tables.
    wasmtime_store_limiter(store, static_cast<std::int64_t>(limits.memory_bytes), 1'000'000, 4, 4, 1);
    cx = wasmtime_store_context(store);
    if (auto *err = wasmtime_context_set_fuel(cx, limits.fuel)) throw std::runtime_error(message_of(err));
    const auto ticks = static_cast<std::uint64_t>(limits.wall / detail::Runtime::kTick) + 1;
    wasmtime_context_set_epoch_deadline(cx, ticks);
  }
  ~Store() { wasmtime_store_delete(store); }
  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;
};

bool get_func(wasmtime_context_t *cx, const wasmtime_instance_t &inst, std::string_view name, wasmtime_func_t &out) {
  wasmtime_extern_t item;
  if (!wasmtime_instance_export_get(cx, &inst, name.data(), name.size(), &item)) return false;
  if (item.kind != WASMTIME_EXTERN_FUNC) {
    wasmtime_extern_delete(&item);
    return false;
  }
  out = item.of.func;
  return true;
}

std::size_t memory_size(wasmtime_context_t *cx, const wasmtime_instance_t &inst) {
  wasmtime_extern_t item;
  if (!wasmtime_instance_export_get(cx, &inst, abi::kExportMemory.data(), abi::kExportMemory.size(), &item)) return 0;
  std::size_t n = item.kind == WASMTIME_EXTERN_MEMORY ? wasmtime_memory_data_size(cx, &item.of.memory) : 0;
  wasmtime_extern_delete(&item);
  return n;
}

}  // namespace

CallResult Plugin::call(std::string_view entry, std::string_view input, FactProvider *facts) const {
  CallResult r;
  CallState st;
  st.facts = facts;
  if (input.size() > static_cast<std::size_t>(INT32_MAX)) {
    r.failure = Failure::plugin_error;
    r.error = "input too large";
    return r;
  }
  {
    Store s(compiled_->runtime->engine, &st, limits_);
    std::optional<Failure> failure;
    std::string error;
    // A trap from wasm comes back as a trap; one raised by a host import
    // comes back as an error. Either way the call state says what happened.
    auto finish = [&](wasm_trap_t *trap, wasmtime_error_t *err, const wasmtime_instance_t *inst) {
      std::optional<wasmtime_trap_code_t> code;
      if (trap) {
        wasmtime_trap_code_t c = 0;
        if (wasmtime_trap_code(trap, &c)) code = c;
        error = clip(message_of(trap));
        wasm_trap_delete(trap);
      }
      if (err) error = clip(message_of(err));
      if (st.host_out_of_fuel || code == WASMTIME_TRAP_CODE_OUT_OF_FUEL) failure = Failure::out_of_fuel;
      else if (code == WASMTIME_TRAP_CODE_INTERRUPT) failure = Failure::timeout;
      else if (st.failed) {
        // fail(): the plugin gave up on purpose, with a message. The SDK's
        // allocator says "out of memory" when memory.grow fails.
        failure = *st.failed == "out of memory" ? Failure::out_of_memory : Failure::plugin_error;
        error = clip(*st.failed);
      }
      // Any other trap with memory within a MiB of its cap is taken to be
      // an allocation failure.
      else if (inst && memory_size(s.cx, *inst) + (1u << 20) > limits_.memory_bytes) failure = Failure::out_of_memory;
      else failure = Failure::trap;
    };

    wasmtime_instance_t inst;
    wasm_trap_t *trap = nullptr;
    wasmtime_error_t *err = wasmtime_instance_pre_instantiate(compiled_->pre, s.cx, &inst, &trap);
    if (err || trap) {
      finish(trap, err, nullptr);
    } else {
      wasmtime_func_t alloc, fn;
      if (!get_func(s.cx, inst, abi::kExportAlloc, alloc) || !get_func(s.cx, inst, entry, fn)) {
        failure = Failure::trap;
        error = "the plugin does not export " + std::string(entry);
      } else {
        wasmtime_val_t arg[2], res;
        arg[0].kind = WASMTIME_I32;
        arg[0].of.i32 = static_cast<std::int32_t>(input.size());
        err = wasmtime_func_call(s.cx, &alloc, arg, 1, &res, 1, &trap);
        if (err || trap) {
          finish(trap, err, &inst);
        } else {
          const std::uint32_t ptr = static_cast<std::uint32_t>(res.of.i32);
          wasmtime_extern_t mem;
          bool placed = false;
          if (wasmtime_instance_export_get(s.cx, &inst, abi::kExportMemory.data(), abi::kExportMemory.size(), &mem)) {
            if (mem.kind == WASMTIME_EXTERN_MEMORY) {
              std::uint8_t *data = wasmtime_memory_data(s.cx, &mem.of.memory);
              std::size_t size = wasmtime_memory_data_size(s.cx, &mem.of.memory);
              if (ptr != 0 && std::uint64_t(ptr) + input.size() <= size) {
                detail::guest_write(data + ptr, input.data(), input.size());
                placed = true;
              }
            }
            wasmtime_extern_delete(&mem);
          }
          if (!placed) {
            failure = memory_size(s.cx, inst) + input.size() + 65536 > limits_.memory_bytes ? Failure::out_of_memory
                                                                                             : Failure::trap;
            error = "rk_alloc(" + std::to_string(input.size()) + ") returned no usable buffer";
          } else {
            arg[0].of.i32 = static_cast<std::int32_t>(ptr);
            arg[1].kind = WASMTIME_I32;
            arg[1].of.i32 = static_cast<std::int32_t>(input.size());
            err = wasmtime_func_call(s.cx, &fn, arg, 2, &res, 1, &trap);
            if (err || trap) finish(trap, err, &inst);
            else if (res.kind != WASMTIME_I32) failure = Failure::trap, error = "entry point returned no i32";
            else if (res.of.i32 != 0) {
              failure = Failure::plugin_error;
              error = st.has_output ? clip(st.output) : "returned " + std::to_string(res.of.i32);
            }
          }
        }
      }
    }
    std::uint64_t left = 0;
    wasmtime_context_get_fuel(s.cx, &left);
    r.fuel_consumed = limits_.fuel - std::min(left, limits_.fuel);
    if (failure) {
      r.failure = *failure;
      r.error = std::move(error);
    }
  }  // the store, and every wasm frame, is gone
  if (st.error) std::rethrow_exception(st.error);
  r.log = std::move(st.log);
  if (r.ok()) r.output = std::move(st.output);
  return r;
}

struct PeripheralInstance::Impl {
  std::shared_ptr<detail::Compiled> compiled;  // keeps the module and engine alive
  Limits limits;
  CallState st;
  wasmtime_store_t *store = nullptr;
  wasmtime_context_t *cx = nullptr;
  wasmtime_instance_t inst{};
  std::uint32_t buffer = 0;
  bool dead = false;
  std::string error;
  std::uint64_t fuel = 0, calls = 0;
  std::map<std::string, std::optional<wasmtime_func_t>> funcs;

  ~Impl() {
    if (store) wasmtime_store_delete(store);
  }

  std::optional<wasmtime_func_t> func(std::string_view name) {
    auto it = funcs.find(std::string(name));
    if (it != funcs.end()) return it->second;
    wasmtime_func_t f;
    std::optional<wasmtime_func_t> r;
    if (get_func(cx, inst, name, f)) r = f;
    funcs[std::string(name)] = r;
    return r;
  }

  // Calls an export with i32/i64 arguments; one result (if any) in `out`.
  bool call(std::string_view name, std::vector<wasmtime_val_t> args, wasmtime_val_t *out, bool required) {
    if (dead) return false;
    auto f = func(name);
    if (!f) {
      if (!required) return true;
      dead = true;
      error = "the plugin does not export " + std::string(name);
      return false;
    }
    ++calls;
    if (auto *err = wasmtime_context_set_fuel(cx, limits.fuel)) message_of(err);
    wasmtime_context_set_epoch_deadline(cx, static_cast<std::uint64_t>(limits.wall / detail::Runtime::kTick) + 1);
    st.host_out_of_fuel = false;
    st.failed.reset();
    wasmtime_val_t res;
    wasm_trap_t *trap = nullptr;
    wasmtime_error_t *err = wasmtime_func_call(cx, &*f, args.data(), args.size(), &res, 1, &trap);
    std::uint64_t left = 0;
    wasmtime_context_get_fuel(cx, &left);
    fuel += limits.fuel - std::min(left, limits.fuel);
    if (err || trap) {
      std::optional<wasmtime_trap_code_t> code;
      std::string msg;
      if (trap) {
        wasmtime_trap_code_t c = 0;
        if (wasmtime_trap_code(trap, &c)) code = c;
        msg = clip(message_of(trap));
        wasm_trap_delete(trap);
      }
      if (err) msg = clip(message_of(err));
      dead = true;
      if (st.host_out_of_fuel || code == WASMTIME_TRAP_CODE_OUT_OF_FUEL) error = "out of fuel in " + std::string(name);
      else if (code == WASMTIME_TRAP_CODE_INTERRUPT) error = "timeout in " + std::string(name);
      else if (st.failed) error = "failed: " + *st.failed;
      else error = "trap in " + std::string(name) + ": " + msg;
      st.error = nullptr;
      return false;
    }
    if (out) *out = res;
    // Entry points that return i32 status: non-zero is a failure.
    if (res.kind == WASMTIME_I32 && name != abi::kExportPeripheralBuffer && name != abi::kExportAlloc && res.of.i32 != 0) {
      dead = true;
      error = std::string(name) + " returned " + std::to_string(res.of.i32);
      return false;
    }
    return true;
  }

  static wasmtime_val_t i32(std::int32_t v) {
    wasmtime_val_t x;
    x.kind = WASMTIME_I32;
    x.of.i32 = v;
    return x;
  }
  static wasmtime_val_t i64(std::int64_t v) {
    wasmtime_val_t x;
    x.kind = WASMTIME_I64;
    x.of.i64 = v;
    return x;
  }

  // Copies bytes into the plugin's input buffer.
  bool put(std::string_view bytes) {
    wasmtime_extern_t mem;
    if (!wasmtime_instance_export_get(cx, &inst, abi::kExportMemory.data(), abi::kExportMemory.size(), &mem)) return false;
    bool ok = false;
    if (mem.kind == WASMTIME_EXTERN_MEMORY) {
      std::uint8_t *data = wasmtime_memory_data(cx, &mem.of.memory);
      const std::size_t size = wasmtime_memory_data_size(cx, &mem.of.memory);
      if (buffer != 0 && std::uint64_t(buffer) + bytes.size() <= size) {
        detail::guest_write(data + buffer, bytes.data(), bytes.size());
        ok = true;
      }
    }
    wasmtime_extern_delete(&mem);
    if (!ok) {
      dead = true;
      error = "rk_peripheral_buffer is outside the plugin's memory";
    }
    return ok;
  }
};

std::unique_ptr<PeripheralInstance> Plugin::instantiate(PeripheralHost &host, std::string &error) const {
  if (manifest_.kind != Kind::peripheral) {
    error = "plugin " + id_ + " is a " + std::string(to_string(manifest_.kind)) + ", not a peripheral";
    return nullptr;
  }
  auto impl = std::make_unique<PeripheralInstance::Impl>();
  impl->compiled = compiled_;
  impl->limits = limits_;
  impl->st.periph = &host;
  impl->store = wasmtime_store_new(compiled_->runtime->engine, &impl->st, nullptr);
  wasmtime_store_limiter(impl->store, static_cast<std::int64_t>(limits_.memory_bytes), 1'000'000, 4, 4, 1);
  impl->cx = wasmtime_store_context(impl->store);
  if (auto *err = wasmtime_context_set_fuel(impl->cx, limits_.fuel)) message_of(err);
  wasmtime_context_set_epoch_deadline(impl->cx, static_cast<std::uint64_t>(limits_.wall / detail::Runtime::kTick) + 1);
  wasm_trap_t *trap = nullptr;
  if (auto *err = wasmtime_instance_pre_instantiate(compiled_->pre, impl->cx, &impl->inst, &trap)) {
    error = "plugin " + id_ + ": cannot instantiate: " + clip(message_of(err));
    return nullptr;
  }
  if (trap) {
    error = "plugin " + id_ + ": trapped while instantiating: " + clip(message_of(trap));
    wasm_trap_delete(trap);
    return nullptr;
  }
  wasmtime_val_t buf;
  if (!impl->call(abi::kExportPeripheralBuffer, {}, &buf, true) || buf.kind != WASMTIME_I32) {
    error = "plugin " + id_ + ": rk_peripheral_buffer: " + (impl->error.empty() ? "returned no i32" : impl->error);
    return nullptr;
  }
  impl->buffer = static_cast<std::uint32_t>(buf.of.i32);
  auto out = std::unique_ptr<PeripheralInstance>(new PeripheralInstance());
  out->impl_ = std::move(impl);
  return out;
}

bool PeripheralInstance::init(std::string_view config) {
  Impl &m = *impl_;
  // The configuration through rk_alloc (once; the instance lives on).
  wasmtime_val_t p;
  if (!m.call(abi::kExportAlloc, {Impl::i32(static_cast<std::int32_t>(config.size()))}, &p, true)) return false;
  if (p.kind != WASMTIME_I32) {
    m.dead = true;
    m.error = "rk_alloc returned no i32";
    return false;
  }
  const std::uint32_t saved = m.buffer;
  m.buffer = static_cast<std::uint32_t>(p.of.i32);
  const bool placed = m.put(config);
  m.buffer = saved;
  if (!placed) return false;
  return m.call(abi::kExportPeripheralInit, {Impl::i32(p.of.i32), Impl::i32(static_cast<std::int32_t>(config.size()))},
                nullptr, true);
}

bool PeripheralInstance::read(std::uint64_t offset, std::uint32_t size, std::uint64_t &value) {
  wasmtime_val_t r;
  if (!impl_->call(abi::kExportPeripheralRead,
                   {Impl::i64(static_cast<std::int64_t>(offset)), Impl::i32(static_cast<std::int32_t>(size))}, &r, true))
    return false;
  value = r.kind == WASMTIME_I64 ? static_cast<std::uint64_t>(r.of.i64) : static_cast<std::uint32_t>(r.of.i32);
  return true;
}

bool PeripheralInstance::write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
  return impl_->call(abi::kExportPeripheralWrite,
                     {Impl::i64(static_cast<std::int64_t>(offset)), Impl::i32(static_cast<std::int32_t>(size)),
                      Impl::i64(static_cast<std::int64_t>(value))},
                     nullptr, true);
}

bool PeripheralInstance::tick(std::uint64_t now) {
  return impl_->call(abi::kExportPeripheralTick, {Impl::i64(static_cast<std::int64_t>(now))}, nullptr, false);
}

bool PeripheralInstance::input(std::string_view bytes) {
  while (!bytes.empty()) {
    const std::string_view part = bytes.substr(0, abi::kPeripheralBuffer);
    if (!impl_->put(part)) return false;
    if (!impl_->call(abi::kExportPeripheralInput,
                     {Impl::i32(static_cast<std::int32_t>(impl_->buffer)), Impl::i32(static_cast<std::int32_t>(part.size()))},
                     nullptr, false))
      return false;
    bytes.remove_prefix(part.size());
  }
  return true;
}

bool PeripheralInstance::irq_in(std::uint32_t line, bool level) {
  return impl_->call(abi::kExportPeripheralIrqIn, {Impl::i32(static_cast<std::int32_t>(line)), Impl::i32(level ? 1 : 0)},
                     nullptr, false);
}

bool PeripheralInstance::reset() { return impl_->call(abi::kExportPeripheralReset, {}, nullptr, false); }

bool Host::available() { return true; }

Host::Host(HostOptions options) : options_(std::move(options)), runtime_(std::make_shared<detail::Runtime>()) {}

std::string wat_to_wasm(std::string_view wat) {
  wasm_byte_vec_t out;
  if (auto *err = wasmtime_wat2wasm(wat.data(), wat.size(), &out)) throw std::runtime_error(message_of(err));
  std::string s(out.data, out.size);
  wasm_byte_vec_delete(&out);
  return s;
}

std::shared_ptr<const Plugin> Host::load(std::string_view manifest_json, std::string_view module,
                                         const std::filesystem::path &origin) {
  Manifest m = parse_manifest(manifest_json);
  const std::string prefix = "plugin " + m.id() + ": ";
  auto fail = [&](const std::string &why) -> std::runtime_error { return std::runtime_error(prefix + why); };
  if (m.interface_version != abi::kInterfaceVersion)
    throw fail("interface version mismatch: the manifest says interface " + std::to_string(m.interface_version) +
               ", this host speaks interface " + std::to_string(abi::kInterfaceVersion));
  if (plugins_.contains(m.name)) throw fail("another plugin is already named " + m.name);

  // Capabilities: requested ones must be granted.
  std::set<Capability> grants = options_.default_grants;
  if (auto it = options_.grants.find(m.name); it != options_.grants.end()) grants.insert(it->second.begin(), it->second.end());
  for (Capability c : m.capabilities)
    if (!grants.contains(c))
      throw fail("requests capability \"" + std::string(to_string(c)) + "\", which is not granted (rk-daemon --plugin-grant " +
                 m.name + "=" + std::string(to_string(c)) + ")");
  if (m.kind == Kind::loader && !m.capabilities.empty())
    throw fail("loaders get the file as their input and take no capabilities");

  std::string bytes = module.substr(0, 4) == std::string_view("\0asm", 4) ? std::string(module) : wat_to_wasm(module);
  auto compiled = std::make_shared<detail::Compiled>();
  compiled->runtime = runtime_;
  wasm_engine_t *engine = runtime_->engine;
  if (auto *err = wasmtime_module_new(engine, reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size(),
                                      &compiled->module))
    throw fail("invalid module: " + clip(message_of(err)));

  // Imports: only revkit:plugin/v1, and only what the capabilities cover.
  {
    wasm_importtype_vec_t imports;
    wasmtime_module_imports(compiled->module, &imports);
    std::string problem;
    for (std::size_t i = 0; i < imports.size && problem.empty(); ++i) {
      const wasm_name_t *mod = wasm_importtype_module(imports.data[i]);
      const wasm_name_t *name = wasm_importtype_name(imports.data[i]);
      std::string mod_s(mod->data, mod->size), name_s(name->data, name->size);
      const std::string what = mod_s + "." + name_s;
      if (mod_s != abi::kImportModule) {
        problem = "imports " + what + ": plugins can import only " + std::string(abi::kImportModule) +
                  " (no WASI: no files, network, clocks, randomness or environment)";
        break;
      }
      const ImportSpec *spec = find_import(name_s);
      if (!spec) problem = "imports " + what + ", which interface " + std::to_string(abi::kInterfaceVersion) + " doesn't have";
      else if (spec->needs_facts && m.kind == Kind::loader) problem = "imports " + what + ", which loaders can't use";
      else if (spec->needs_facts && m.kind == Kind::peripheral)
        problem = "imports " + what + ", which peripherals can't use (they see the emulated machine)";
      else if (spec->peripheral && m.kind != Kind::peripheral) problem = "imports " + what + ", which only peripherals can use";
      else if (spec->capability && !m.capabilities.contains(*spec->capability))
        problem = "imports " + what + ", which needs capability \"" + std::string(to_string(*spec->capability)) +
                  "\"; request it in the manifest";
    }
    wasm_importtype_vec_delete(&imports);
    if (!problem.empty()) throw fail(problem);
  }

  // Exports: memory and the kind's entry point, and initial memory within
  // the cap.
  Limits limits = options_.defaults;
  if (m.fuel) limits.fuel = std::min(m.fuel, options_.maximum.fuel);
  if (m.memory_bytes) limits.memory_bytes = std::min(m.memory_bytes, options_.maximum.memory_bytes);
  const std::string_view entry = m.kind == Kind::analyzer   ? abi::kExportAnalyze
                                 : m.kind == Kind::loader   ? abi::kExportLoad
                                 : m.kind == Kind::command  ? abi::kExportCommand
                                                            : abi::kExportPeripheralRead;
  if (m.kind == Kind::peripheral && !m.fuel) limits.fuel = 50'000'000;  // per register access or tick
  {
    wasm_exporttype_vec_t exports;
    wasmtime_module_exports(compiled->module, &exports);
    std::map<std::string, wasm_externkind_t> have;
    std::uint64_t initial_pages = 0;
    for (std::size_t i = 0; i < exports.size; ++i) {
      const wasm_name_t *name = wasm_exporttype_name(exports.data[i]);
      const wasm_externtype_t *type = wasm_exporttype_type(exports.data[i]);
      std::string n(name->data, name->size);
      have[n] = wasm_externtype_kind(type);
      if (n == abi::kExportMemory && have[n] == WASM_EXTERN_MEMORY)
        initial_pages = wasm_memorytype_limits(wasm_externtype_as_memorytype_const(type))->min;
    }
    wasm_exporttype_vec_delete(&exports);
    std::vector<std::string_view> needs = {abi::kExportVersion, abi::kExportAlloc, entry};
    if (m.kind == Kind::peripheral)
      needs.insert(needs.end(), {abi::kExportPeripheralBuffer, abi::kExportPeripheralInit, abi::kExportPeripheralWrite});
    for (std::string_view need : needs)
      if (!have.contains(std::string(need)) || have[std::string(need)] != WASM_EXTERN_FUNC)
        throw fail("does not export function " + std::string(need) + " (a " + std::string(to_string(m.kind)) + " must)");
    if (!have.contains(std::string(abi::kExportMemory)) || have[std::string(abi::kExportMemory)] != WASM_EXTERN_MEMORY)
      throw fail("does not export its memory as \"memory\"");
    if (initial_pages * 65536 > limits.memory_bytes)
      throw fail("initial memory (" + std::to_string(initial_pages * 64) + " KiB) exceeds its cap (" +
                 std::to_string(limits.memory_bytes >> 10) + " KiB)");
  }

  // The linker defines only the imports the plugin may use.
  compiled->linker = wasmtime_linker_new(engine);
  for (const ImportSpec &spec : import_specs()) {
    if (spec.needs_facts && (m.kind == Kind::loader || m.kind == Kind::peripheral)) continue;
    if (spec.peripheral && m.kind != Kind::peripheral) continue;
    if (spec.capability && !m.capabilities.contains(*spec.capability)) continue;
    wasm_functype_t *ft = functype(spec.params, spec.results);
    wasmtime_error_t *err = wasmtime_linker_define_func(
        compiled->linker, abi::kImportModule.data(), abi::kImportModule.size(), spec.name.data(), spec.name.size(), ft,
        dispatch, reinterpret_cast<void *>(static_cast<std::uintptr_t>(spec.id)), nullptr);
    wasm_functype_delete(ft);
    if (err) throw fail("cannot define import " + std::string(spec.name) + ": " + message_of(err));
  }
  if (auto *err = wasmtime_linker_instantiate_pre(compiled->linker, compiled->module, &compiled->pre))
    throw fail("cannot link: " + clip(message_of(err)));

  auto p = std::shared_ptr<Plugin>(new Plugin());
  p->manifest_ = m;
  p->id_ = m.id();
  p->fingerprint_ = facts::Fingerprint::of(bytes).hex();
  p->granted_ = m.capabilities;
  p->limits_ = limits;
  p->path_ = origin;
  p->compiled_ = std::move(compiled);

  // The module's own idea of its interface version must agree.
  {
    CallState st;
    Limits probe{10'000'000, limits.memory_bytes, std::chrono::seconds(5)};
    Store s(engine, &st, probe);
    wasmtime_instance_t inst;
    wasm_trap_t *trap = nullptr;
    wasmtime_error_t *err = wasmtime_instance_pre_instantiate(p->compiled_->pre, s.cx, &inst, &trap);
    if (err) throw fail("cannot instantiate: " + clip(message_of(err)));
    if (trap) {
      std::string msg = message_of(trap);
      wasm_trap_delete(trap);
      throw fail("trapped while instantiating: " + clip(msg));
    }
    wasmtime_func_t fn;
    get_func(s.cx, inst, abi::kExportVersion, fn);
    wasmtime_val_t res;
    err = wasmtime_func_call(s.cx, &fn, nullptr, 0, &res, 1, &trap);
    if (err) throw fail("rk_abi_version: " + clip(message_of(err)));
    if (trap) {
      std::string msg = message_of(trap);
      wasm_trap_delete(trap);
      throw fail("rk_abi_version trapped: " + clip(msg));
    }
    if (res.kind != WASMTIME_I32 || static_cast<std::uint32_t>(res.of.i32) != m.interface_version)
      throw fail("interface version mismatch: the module was built for interface " +
                 (res.kind == WASMTIME_I32 ? std::to_string(res.of.i32) : std::string("?")) + ", the manifest says " +
                 std::to_string(m.interface_version));
  }

  register_plugin(p);
  plugins_[m.name] = p;
  return p;
}

#else  // !REVKIT_HAVE_WASMTIME

namespace detail {
struct Runtime {};
struct Compiled {};
}  // namespace detail

CallResult Plugin::call(std::string_view, std::string_view, FactProvider *) const {
  CallResult r;
  r.failure = Failure::trap;
  r.error = "revkit was built without the WebAssembly runtime";
  return r;
}

struct PeripheralInstance::Impl {
  bool dead = true;
  std::string error = "revkit was built without the WebAssembly runtime";
  std::uint64_t fuel = 0, calls = 0;
};

std::unique_ptr<PeripheralInstance> Plugin::instantiate(PeripheralHost &, std::string &error) const {
  error = "revkit was built without the WebAssembly runtime";
  return nullptr;
}

bool PeripheralInstance::init(std::string_view) { return false; }
bool PeripheralInstance::read(std::uint64_t, std::uint32_t, std::uint64_t &) { return false; }
bool PeripheralInstance::write(std::uint64_t, std::uint32_t, std::uint64_t) { return false; }
bool PeripheralInstance::tick(std::uint64_t) { return false; }
bool PeripheralInstance::input(std::string_view) { return false; }
bool PeripheralInstance::irq_in(std::uint32_t, bool) { return false; }
bool PeripheralInstance::reset() { return false; }

bool Host::available() { return false; }

Host::Host(HostOptions options) : options_(std::move(options)) {}

std::string wat_to_wasm(std::string_view) {
  throw std::runtime_error("revkit was built without the WebAssembly runtime (REVKIT_PLUGINS=OFF)");
}

std::shared_ptr<const Plugin> Host::load(std::string_view manifest_json, std::string_view, const std::filesystem::path &) {
  Manifest m = parse_manifest(manifest_json);
  throw std::runtime_error("plugin " + m.id() +
                           ": revkit was built without the WebAssembly runtime (configure with -DREVKIT_PLUGINS=ON)");
}

#endif

Host::~Host() = default;

PeripheralInstance::~PeripheralInstance() = default;
bool PeripheralInstance::dead() const { return impl_->dead; }
const std::string &PeripheralInstance::error() const { return impl_->error; }
std::uint64_t PeripheralInstance::fuel_used() const { return impl_->fuel; }
std::uint64_t PeripheralInstance::calls() const { return impl_->calls; }

std::shared_ptr<const Plugin> Host::load(const std::filesystem::path &wasm) {
  std::filesystem::path manifest = wasm;
  manifest.replace_extension(".json");
  if (!std::filesystem::exists(manifest))
    throw std::runtime_error(wasm.string() + ": no manifest (expected " + manifest.filename().string() + " beside it)");
  return load(read_file(manifest), read_file(wasm), wasm);
}

std::vector<Rejected> Host::load_dir(const std::filesystem::path &dir) {
  std::vector<std::filesystem::path> files;
  std::error_code ec;
  for (const auto &e : std::filesystem::directory_iterator(dir, ec))
    if (e.is_regular_file() && e.path().extension() == ".wasm") files.push_back(e.path());
  if (ec) throw std::runtime_error("cannot list " + dir.string() + ": " + ec.message());
  std::sort(files.begin(), files.end());
  std::vector<Rejected> out;
  for (const auto &f : files) {
    try {
      load(f);
    } catch (const std::exception &e) {
      Rejected r{f, {}, {}, e.what()};
      std::filesystem::path manifest = f;
      manifest.replace_extension(".json");
      try {
        Manifest m = parse_manifest(read_file(manifest));
        r.name = m.name;
        r.version = m.version;
      } catch (const std::exception &) {
      }
      out.push_back(r);
      rejected_.push_back(std::move(r));
    }
  }
  return out;
}

std::vector<std::shared_ptr<const Plugin>> Host::plugins() const {
  std::vector<std::shared_ptr<const Plugin>> out;
  for (const auto &[name, p] : plugins_) out.push_back(p);
  return out;
}

std::shared_ptr<const Plugin> Host::find(const std::string &name) const {
  auto it = plugins_.find(name);
  return it == plugins_.end() ? nullptr : it->second;
}

// ---- typed calls -------------------------------------------------------------

namespace {

constexpr std::size_t kMaxText = 4096;
constexpr std::size_t kMaxSub = 64;
constexpr std::size_t kMaxItems = 1'000'000;

void bad_output(CallResult &r, const std::string &why) {
  r.failure = Failure::bad_output;
  r.error = why;
  r.output.clear();
}

bool valid_utf8(std::string_view s) {
  for (std::size_t i = 0; i < s.size();) {
    auto c = static_cast<unsigned char>(s[i]);
    std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (!n || i + n > s.size()) return false;
    for (std::size_t k = 1; k < n; ++k)
      if ((static_cast<unsigned char>(s[i + k]) >> 6) != 2) return false;
    i += n;
  }
  return true;
}

std::string text(abi::Reader &r, std::size_t max, const char *what) {
  std::string_view s = r.str();
  if (s.size() > max) throw abi::AbiError(std::string(what) + " longer than " + std::to_string(max) + " bytes");
  if (!valid_utf8(s)) throw abi::AbiError(std::string(what) + " is not UTF-8");
  return std::string(s);
}

}  // namespace

CallResult run_analyzer(const Plugin &p, abi::Scope scope, std::uint64_t address, FactProvider &facts,
                        std::vector<DerivedItem> &out) {
  out.clear();
  abi::Writer w;
  auto rec = w.begin();
  w.u8(static_cast<std::uint8_t>(scope));
  w.u64(address);
  w.end_record(rec);
  CallResult r = p.call(abi::kExportAnalyze, w.bytes(), &facts);
  if (!r.ok()) return r;
  try {
    abi::Reader rd(r.output);
    std::uint32_t n = rd.list(4);
    if (n > kMaxItems) throw abi::AbiError("too many facts");
    for (std::uint32_t i = 0; i < n; ++i) {
      abi::Reader f = rd.record();
      DerivedItem item;
      std::uint8_t kind = f.u8();
      if (kind < 1 || kind > 4) throw abi::AbiError("unknown fact kind " + std::to_string(kind));
      item.kind = static_cast<abi::FactKind>(kind);
      item.address = f.u64();
      item.text = text(f, kMaxText, "fact text");
      item.sub = text(f, kMaxSub, "fact sub");
      out.push_back(std::move(item));
    }
    if (!rd.done()) throw abi::AbiError("trailing bytes");
  } catch (const abi::AbiError &e) {
    out.clear();
    bad_output(r, std::string("analyzer result: ") + e.what());
  }
  return r;
}

bool loader_matches(const Plugin &p, std::string_view file) {
  const Manifest &m = p.manifest();
  if (m.kind != Kind::loader || m.magic.empty() || m.magic_offset > file.size()) return false;
  return file.substr(m.magic_offset, m.magic.size()) == m.magic;
}

CallResult run_loader(const Plugin &p, std::string_view file, LoadResult &out) {
  out = {};
  CallResult r = p.call(abi::kExportLoad, file, nullptr);
  if (!r.ok()) return r;
  try {
    abi::Reader rd(r.output);
    abi::Reader res = rd.record();
    out.language = text(res, 128, "language");
    out.compiler = text(res, 64, "compiler");
    if (out.language.empty()) throw abi::AbiError("no language");
    if (res.u8()) out.entry = res.u64();
    else res.u64();
    std::uint32_t nb = res.list(4);
    if (nb == 0 || nb > 4096) throw abi::AbiError("a load needs 1 to 4096 blocks");
    for (std::uint32_t i = 0; i < nb; ++i) {
      abi::Reader b = res.record();
      LoadedBlock blk;
      blk.name = text(b, 256, "block name");
      blk.start = b.u64();
      blk.size = b.u64();
      blk.file_offset = b.u64();
      blk.file_size = b.u64();
      blk.perms = b.u8();
      if (blk.size == 0 || blk.start + (blk.size - 1) < blk.start) throw abi::AbiError("block " + blk.name + " is empty or wraps");
      if (blk.file_size > blk.size) throw abi::AbiError("block " + blk.name + " has more file bytes than its size");
      if (blk.file_offset > file.size() || blk.file_size > file.size() - blk.file_offset)
        throw abi::AbiError("block " + blk.name + " lies outside the file");
      out.blocks.push_back(std::move(blk));
    }
    std::uint32_t ns = res.list(4);
    if (ns > kMaxItems) throw abi::AbiError("too many symbols");
    for (std::uint32_t i = 0; i < ns; ++i) {
      abi::Reader s = res.record();
      LoadedSymbol sym;
      sym.name = text(s, 1024, "symbol name");
      sym.address = s.u64();
      sym.size = s.u64();
      sym.function = s.u8() != 0;
      out.symbols.push_back(std::move(sym));
    }
    if (!rd.done()) throw abi::AbiError("trailing bytes");
  } catch (const abi::AbiError &e) {
    out = {};
    bad_output(r, std::string("loader result: ") + e.what());
  }
  return r;
}

CallResult run_command(const Plugin &p, const std::string &program_id, const std::map<std::string, std::string> &args,
                       FactProvider &facts, std::vector<Edit> &out) {
  out.clear();
  const Manifest &m = p.manifest();
  for (const auto &[k, v] : args)
    if (std::none_of(m.args.begin(), m.args.end(), [&](const CommandArg &a) { return a.name == k; }))
      throw std::invalid_argument(m.id() + " takes no argument \"" + k + "\"");
  for (const CommandArg &a : m.args)
    if (a.required && !args.contains(a.name)) throw std::invalid_argument(m.id() + " needs argument \"" + a.name + "\"");
  abi::Writer w;
  auto rec = w.begin();
  w.str(program_id);
  auto list = w.begin();
  for (const auto &[k, v] : args) {
    auto item = w.begin();
    w.str(k);
    w.str(v);
    w.end_record(item);
  }
  w.end_list(list, static_cast<std::uint32_t>(args.size()));
  w.end_record(rec);
  CallResult r = p.call(abi::kExportCommand, w.bytes(), &facts);
  if (!r.ok()) return r;
  try {
    abi::Reader rd(r.output);
    std::uint32_t n = rd.list(4);
    if (n > 100'000) throw abi::AbiError("more than 100000 edits");
    for (std::uint32_t i = 0; i < n; ++i) {
      abi::Reader e = rd.record();
      Edit edit;
      std::uint8_t op = e.u8();
      if (op < 1 || op > 4) throw abi::AbiError("unknown edit op " + std::to_string(op));
      edit.op = static_cast<abi::EditOp>(op);
      edit.address = e.u64();
      edit.text = text(e, kMaxText, "edit text");
      edit.sub = text(e, kMaxSub, "edit sub");
      out.push_back(std::move(edit));
    }
    if (!rd.done()) throw abi::AbiError("trailing bytes");
  } catch (const abi::AbiError &e) {
    out.clear();
    bad_output(r, std::string("command result: ") + e.what());
  }
  return r;
}

}  // namespace revkit::plugins
