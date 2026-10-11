#include "revkit/plugins/peripheral.h"

namespace revkit::plugins {

namespace {

class PluginPeripheral final : public emu::Peripheral, public PeripheralHost {
 public:
  PluginPeripheral(std::shared_ptr<const Plugin> plugin, const emu::PeripheralSpec &spec)
      : plugin_(std::move(plugin)), name_(spec.name), config_(spec.config.compact()) {}

  bool start(std::string &error) {
    instance_ = plugin_->instantiate(*this, error);
    return instance_ != nullptr;
  }

  // --- emu::Peripheral ---
  std::uint64_t read(std::uint64_t offset, std::uint32_t size) override {
    std::uint64_t v = 0;
    if (alive() && !instance_->read(offset, size, v)) failed();
    return v;
  }
  void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override {
    if (alive() && !instance_->write(offset, size, value)) failed();
  }
  void tick(std::uint64_t now) override {
    if (alive() && !instance_->tick(now)) failed();
  }
  void input(std::string_view bytes) override {
    if (alive() && !instance_->input(bytes)) failed();
  }
  void irq_in(unsigned line, bool level) override {
    if (alive() && !instance_->irq_in(line, level)) failed();
  }
  std::vector<std::string> outputs() const override { return plugin_->manifest().outputs; }
  bool has_inputs() const override { return plugin_->manifest().inputs > 0; }
  std::optional<std::uint64_t> default_size() const override { return plugin_->manifest().region_size; }
  void reset() override {
    if (!initialized_) {
      initialized_ = true;
      if (!instance_->init(config_)) failed();
    } else if (alive() && !instance_->reset()) {
      failed();
    }
  }
  std::string state() const override {
    std::string s = plugin_->id() + ", " + std::to_string(instance_->calls()) + " calls, " +
                    std::to_string(instance_->fuel_used()) + " fuel";
    if (instance_->dead()) s += "; failed: " + instance_->error();
    return s;
  }

  // --- PeripheralHost (the plugin's imports) ---
  std::uint64_t now() override { return ctx().now(); }
  void schedule(std::int64_t at) override {
    if (at < 0) ctx().cancel_schedule();
    else ctx().schedule(static_cast<std::uint64_t>(at));
  }
  void irq(std::uint32_t line, bool level) override {
    if (line < plugin_->manifest().outputs.size()) ctx().set_irq(line, level);
  }
  void output(std::string_view bytes) override { ctx().output(bytes); }
  bool bus_read(std::uint64_t address, std::span<std::uint8_t> out) override { return ctx().read_memory(address, out); }
  bool bus_write(std::uint64_t address, std::span<const std::uint8_t> bytes) override {
    return ctx().write_memory(address, bytes);
  }
  void log(std::string_view line) override { ctx().log(line); }

 private:
  bool alive() const { return instance_ && !instance_->dead(); }
  void failed() {
    if (reported_) return;
    reported_ = true;
    ctx().request_stop("peripheral " + name_ + " (plugin " + plugin_->id() + ") failed: " + instance_->error());
  }

  std::shared_ptr<const Plugin> plugin_;
  std::string name_, config_;
  std::unique_ptr<PeripheralInstance> instance_;
  bool initialized_ = false, reported_ = false;
};

}  // namespace

emu::PeripheralFactory peripheral_factory(const Host &host) {
  return [&host](const emu::PeripheralSpec &spec, std::string &error) -> std::unique_ptr<emu::Peripheral> {
    if (spec.kind.rfind("plugin:", 0) != 0) return nullptr;
    const std::string name = spec.kind.substr(7);
    auto plugin = host.find(name);
    if (!plugin) {
      error = "no plugin named " + name + " is loaded (rk-daemon --plugin-dir)";
      return nullptr;
    }
    if (plugin->manifest().kind != Kind::peripheral) {
      error = "plugin " + plugin->id() + " is a " + std::string(to_string(plugin->manifest().kind)) + ", not a peripheral";
      return nullptr;
    }
    auto p = std::make_unique<PluginPeripheral>(plugin, spec);
    if (!p->start(error)) return nullptr;
    return p;
  };
}

}  // namespace revkit::plugins
