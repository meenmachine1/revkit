// A starter machine for a program (derive_machine): memory from its blocks
// and the MMIO its code reaches, then trial runs that add MMIO regions where
// it faults on unmapped memory and auto-ack registers for the polling loops
// it spins in. Everything here is a first draft for a person to refine;
// the notes say what was guessed.
#include "machine_impl.hh"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace revkit::emu {

namespace {

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

bool inside(const std::vector<MemorySpec> &mem, std::uint64_t a) {
  for (const MemorySpec &m : mem)
    if (a >= m.start && a - m.start < m.size) return true;
  return false;
}

// Regions for addresses outside the memory: pages within `join` of each
// other make one region.
std::vector<std::pair<std::uint64_t, std::uint64_t>> cluster(std::vector<std::uint64_t> addrs, std::uint64_t join) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> out;  // [start, end)
  std::sort(addrs.begin(), addrs.end());
  for (std::uint64_t a : addrs) {
    const std::uint64_t page = a & ~std::uint64_t{0xfff};
    if (!out.empty() && page <= out.back().second + join) out.back().second = std::max(out.back().second, page + 0x1000);
    else out.emplace_back(page, page + 0x1000);
  }
  return out;
}

struct Trial {
  Stop stop;
  std::uint64_t steps = 0;
  std::uint64_t pcs = 0;  // distinct instructions run
  // The address a polling loop reads, if the last window spun on one.
  std::optional<std::uint64_t> hot;
  std::uint64_t hot_reads = 0;
};

constexpr std::uint64_t kWindow = 100000;

// Runs the program on `spec` for up to `steps` steps, in windows; stops early
// at the first window that spins on one MMIO address (when `find_hot`).
Trial trial(const std::shared_ptr<const loader::Image> &image, const std::string &language, const MachineSpec &spec,
            std::uint64_t steps, bool find_hot, const DeriveOptions &o, const std::set<std::uint64_t> &answered) {
  Trial t;
  Options eo;
  eo.language = language;
  eo.trace_capacity = 0;
  eo.mmio_log_capacity = 0;
  Emulator e(image, eo);
  e.attach_machine(spec, {});
  std::map<std::uint64_t, std::uint64_t> reads;
  std::uint64_t all_reads = 0;
  e.on_mmio([&](Emulator &, MmioAccess &a) {
    if (a.write) return;
    ++reads[a.address];
    ++all_reads;
  });
  while (t.steps < steps) {
    reads.clear();
    all_reads = 0;
    RunOptions ro;
    ro.max_steps = std::min(kWindow, steps - t.steps);
    ro.deadline = o.deadline;
    t.stop = e.run(ro);
    t.steps = e.steps();
    if (t.stop.kind != StopKind::step_limit) break;
    if (!find_hot) continue;
    // A polling loop: one register read hundreds of times, most of the window's reads.
    for (const auto &[addr, n] : reads)
      if (n >= 300 && 2 * n >= all_reads && !answered.count(addr) && (!t.hot || n > t.hot_reads)) {
        t.hot = addr;
        t.hot_reads = n;
      }
    if (t.hot) break;
  }
  t.pcs = e.trace().summary().unique_pcs;
  return t;
}

}  // namespace

DerivedMachine derive_machine(std::shared_ptr<const loader::Image> image, const std::string &language,
                              const std::vector<StaticAccess> &accesses, const std::optional<ImageSpec> &image_spec,
                              const DeriveOptions &o) {
  DerivedMachine out;
  MachineSpec &s = out.spec;
  auto note = [&](std::string n) { out.notes.push_back(std::move(n)); };
  s.name = "starter";
  s.description = "derived by revkit from the program: refine the memory, add peripherals and wire their interrupts";
  s.language = language;
  s.cpu.model = detail::default_cpu_model(language);
  s.image = image_spec;

  // Memory: the program's blocks.
  for (const loader::Block &b : image->blocks) {
    MemorySpec m;
    m.name = b.name.empty() ? "block_" + hexs(b.start).substr(2) : b.name;
    m.start = b.start;
    m.size = b.size;
    m.perms = b.perms;
    m.kind = b.is_volatile ? MemorySpec::Kind::mmio : (!b.perms.write && b.initialized) ? MemorySpec::Kind::rom : MemorySpec::Kind::ram;
    if (m.size == 0 || inside(s.memory, m.start)) continue;
    s.memory.push_back(m);
  }
  if (image_spec) {
    // The image as the machine loads it, if no block covers it.
    const loader::Block *b = image->blocks.empty() ? nullptr : &image->blocks.front();
    if (b && !inside(s.memory, image_spec->load)) note("the image's block isn't at its load address: check \"image\"");
  }
  note("memory: the program's " + std::to_string(s.memory.size()) + " blocks");

  // What the code reaches outside them, and in MMIO.
  std::set<std::uint64_t> mmio_addrs;
  std::vector<std::uint64_t> outside;
  for (const StaticAccess &a : accesses) {
    bool mmio = false;
    for (const MemorySpec &m : s.memory)
      if (a.address >= m.start && a.address - m.start < m.size) mmio = m.kind == MemorySpec::Kind::mmio;
    if (mmio) mmio_addrs.insert(a.address);
    else if (!inside(s.memory, a.address)) outside.push_back(a.address);
  }
  const bool cortex = s.cpu.model == "cortex-m";
  std::vector<std::uint64_t> ram_like, io_like;
  for (std::uint64_t a : outside) {
    if (cortex && a >= 0xe0000000) continue;  // the system control space is the CPU's
    if (cortex && a >= 0x20000000 && a < 0x40000000) ram_like.push_back(a);
    else io_like.push_back(a);
  }
  for (const auto &[start, end] : cluster(ram_like, 0x100000)) {
    MemorySpec m;
    m.name = "sram_" + hexs(start).substr(2);
    m.start = start & ~std::uint64_t{0xffff};
    m.size = ((end + 0xffff) & ~std::uint64_t{0xffff}) - m.start;
    m.kind = MemorySpec::Kind::ram;
    if (inside(s.memory, m.start)) continue;
    s.memory.push_back(m);
    note("RAM " + m.name + " " + hexs(m.start) + "+" + hexs(m.size) + ": the code reads and writes globals there");
  }
  for (const auto &[start, end] : cluster(io_like, 0x10000)) {
    MemorySpec m;
    m.name = "mmio_" + hexs(start).substr(2);
    m.start = start;
    m.size = end - start;
    m.kind = MemorySpec::Kind::mmio;
    m.perms = {true, true, false};
    bool clash = false;
    for (const MemorySpec &x : s.memory) clash = clash || (m.start < x.start + x.size && x.start < m.start + m.size);
    if (clash) continue;
    s.memory.push_back(m);
    std::size_t n = 0;
    for (std::uint64_t a : io_like) n += a >= start && a < end;
    note("MMIO " + m.name + " " + hexs(m.start) + "+" + hexs(m.size) + ": " + std::to_string(n) +
         " constant-address accesses outside the program's memory");
  }
  for (std::uint64_t a : io_like) mmio_addrs.insert(a);
  out.mmio_registers = static_cast<std::uint32_t>(mmio_addrs.size());

  // Where it starts.
  if (cortex) {
    std::uint64_t lo = ~std::uint64_t{0};
    for (const loader::Block &b : image->blocks)
      if (b.initialized && !b.is_volatile) lo = std::min(lo, b.start);
    if (lo != ~std::uint64_t{0}) s.cpu.vector_base = lo;
    note("Cortex-M: SP and PC from the vector table at " + hexs(s.cpu.vector_base.value_or(0)));
  } else if (s.cpu.model == "arm") {
    if (image->entry && *image->entry != 0) s.entry = *image->entry;
    note(s.entry ? "entry: the program's entry point" : "entry: the reset vector at 0");
  } else if (image->entry) {
    s.entry = *image->entry;
  }

  // Trial runs: faults on unmapped memory become MMIO regions; polling
  // loops get auto-ack registers.
  if (o.trial_steps > 0 && !s.cpu.model.empty()) {
    std::set<std::uint64_t> answered;
    json::Value rules = json::Value::array();
    auto ack_spec = [&](const json::Value &r) {
      MachineSpec x = s;
      PeripheralSpec p;
      p.name = "acks";
      p.kind = "auto-ack";
      p.config = json::Value::object();
      p.config.set("name", json::Value::string("acks"));
      p.config.set("kind", json::Value::string("auto-ack"));
      p.config.set("registers", r);
      p.size = 0x1000;
      if (!r.items().empty()) x.peripherals.push_back(p);
      return x;
    };
    std::size_t runs = 0;
    while (runs < o.max_runs && std::chrono::steady_clock::now() < o.deadline) {
      ++runs;
      Trial t;
      try {
        t = trial(image, language, ack_spec(rules), o.trial_steps, out.polling_loops < o.max_loops, o, answered);
      } catch (const EmuError &e) {
        note(std::string("the trial run couldn't start: ") + e.what());
        break;
      }
      out.trial_steps = t.steps;
      out.trial_stop = t.stop;
      if (t.stop.kind == StopKind::unmapped && t.stop.address && *t.stop.address != t.stop.pc) {
        const std::uint64_t a = *t.stop.address;
        MemorySpec m;
        m.start = a & ~std::uint64_t{0xffff};
        m.size = 0x10000;
        m.name = "mmio_" + hexs(m.start).substr(2);
        m.kind = MemorySpec::Kind::mmio;
        m.perms = {true, true, false};
        bool clash = false;
        for (const MemorySpec &x : s.memory) clash = clash || (m.start < x.start + x.size && x.start < m.start + m.size);
        if (clash) {
          note("the trial run stopped: " + t.stop.detail);
          break;
        }
        s.memory.push_back(m);
        note("MMIO " + m.name + " " + hexs(m.start) + "+" + hexs(m.size) + ": the trial run accessed " + hexs(a) + " (from " +
             hexs(t.stop.pc) + ")");
        continue;
      }
      if (!t.hot) break;
      // A polling loop: the first answer that gets the code past it.
      const std::uint64_t hot = *t.hot;
      answered.insert(hot);
      struct Candidate {
        const char *mode;
        std::uint64_t mask, value, step;
        const char *why;
      };
      const Candidate cands[] = {
          {"fixed", 0xffffffff, 0xffffffff, 0, "reads all ones (a ready bit set)"},
          {"fixed", 0xffffffff, 0, 0, "reads zero (a busy bit clear)"},
          {"increment", 0xffffffff, 0, 0x100, "counts up by 0x100 on each read (a free-running counter)"},
          {"toggle", 0xffffffff, 0xffffffff, 0, "toggles all its bits on each read"},
      };
      bool solved = false;
      // How far the code gets without an answer, to compare.
      Trial base;
      try {
        base = trial(image, language, ack_spec(rules), t.steps + 4 * kWindow, false, o, {});
        ++runs;
      } catch (const EmuError &) {
      }
      // Each answer, kept if the code gets furthest with it.
      std::optional<std::pair<json::Value, const Candidate *>> best;
      std::uint64_t best_pcs = base.pcs + 16;
      for (const Candidate &c : cands) {
        if (runs >= o.max_runs || std::chrono::steady_clock::now() >= o.deadline) break;
        ++runs;
        json::Value r = json::Value::object();
        r.set("address", json::Value::string(hexs(hot)));
        r.set("mode", json::Value::string(c.mode));
        r.set("mask", json::Value::string(hexs(c.mask)));
        if (std::string(c.mode) != "increment") r.set("value", json::Value::string(hexs(c.value)));
        else r.set("step", json::Value::string(hexs(c.step)));
        r.set("note", json::Value::string(std::string("polled by the code; ") + c.why));
        json::Value with = rules;
        with.push(r);
        Trial u;
        try {
          u = trial(image, language, ack_spec(with), t.steps + 4 * kWindow, false, o, {});
        } catch (const EmuError &) {
          continue;
        }
        // Past the loop: the code reaches instructions it didn't.
        if (u.pcs < best_pcs) continue;
        best_pcs = u.pcs;
        best = std::make_pair(with, &c);
      }
      if (best) {
        rules = best->first;
        ++out.polling_loops;
        note("auto-ack " + hexs(hot) + ": the code polls it (" + std::to_string(t.hot_reads) +
             " reads in 100000 steps); " + best->second->why + " gets it furthest (" + std::to_string(best_pcs - base.pcs) +
             " more instructions reached)");
        solved = true;
      }
      if (!solved) {
        note("the code polls " + hexs(hot) + " and no simple answer gets it past: model that register");
        break;
      }
    }
    if (!rules.items().empty()) s = ack_spec(rules);
    note("trial run: " + std::to_string(out.trial_steps) + " steps, stopped (" + std::string(to_string(out.trial_stop.kind)) +
         ") at " + hexs(out.trial_stop.pc) + (out.trial_stop.detail.empty() ? "" : ": " + out.trial_stop.detail));
  }

  // The description, with the notes in it.
  json::Value doc = json::Value::parse(machine_json(s));
  json::Value notes = json::Value::array();
  for (const std::string &n : out.notes) notes.push(json::Value::string(n));
  json::Value with = json::Value::object();
  for (const auto &[k, v] : doc.members()) {
    with.set(k, v);
    if (k == "description") with.set("note", notes);
  }
  if (!with.find("note")) with.set("note", notes);
  out.json = with.dump() + "\n";
  out.spec.source = with;
  return out;
}

}  // namespace revkit::emu
