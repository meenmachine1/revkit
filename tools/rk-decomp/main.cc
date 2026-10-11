// rk-decomp: decompile one function using Ghidra's decompiler linked as a
// library (no Java, no pipe). Takes an ELF or PE executable, or a raw binary.
//
//   rk-decomp --file <elf|pe> (--symbol <name> | --addr <hex>) [--lang <id>] [--ghidra <root>]
//   rk-decomp --file <raw.bin> --addr <hex> [--lang <id>] [--ghidra <root>]
//   rk-decomp --file <firmware> --addr <hex> --lang <id> [--raw] [--base <hex>] [--raw-offset <hex>]
//             [--raw-length <hex>] [--raw-perms <rwx>] [--region <name:start:size[:perms][:init|uninit|volatile]>]...

#include "libdecomp.hh"
#include "raw_arch.hh"

#include "revkit/lift/functions.hh"
#include "revkit/runtime/runtime.h"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr const char *kDefaultRawLanguage = "x86:LE:64:default:gcc";

struct Options {
  std::string ghidra_root;
  std::optional<std::string> language;
  std::string file;
  std::optional<unsigned long long> addr;
  std::optional<std::string> symbol;
  std::optional<unsigned long long> base;
  bool file_base = false;
  bool raw = false;
  // A raw image laid out as revkit's loader does (rk-lift --raw): set by
  // any of --raw-offset, --raw-length, --raw-perms and --region, or --base
  // with --raw.
  bool raw_layout = false;
  revkit::loader::RawOptions raw_options;
};

void usage(std::ostream &os) {
  os << "usage: rk-decomp --file <binary> (--symbol <name> | --addr <hex>) [options]\n"
        "  --file       ELF or PE executable, or a raw binary (byte 0 is address 0)\n"
        "  --symbol     function to decompile, by symbol name (ELF/PE only)\n"
        "  --addr       function entry point, hex (e.g. 0x401000)\n"
        "  --lang       Ghidra language id with compiler (default: from the file;\n"
        "               raw files default to x86:LE:64:default:gcc)\n"
        "  --raw        treat --file as raw bytes even if it looks like ELF/PE\n"
        "  --base       load ELF/PE at this image base, hex\n"
        "  --file-base  keep the file's own base (default: Ghidra's, 0x100000 for 64-bit PIE)\n"
        "  Raw images laid out as rk-lift --raw does (implies --raw; --base is then the image's address):\n"
        "  --raw-offset <hex>  skip this many bytes of the file (a header)\n"
        "  --raw-length <hex>  load this many bytes (default: to the end of the file)\n"
        "  --raw-perms <rwx>   the image block's permissions (default rwx, as Ghidra's raw loader)\n"
        "  --raw-space <name>  the memory space the image goes in; --raw-format binary|ihex|srec|detect\n"
        "  --region <name:start:size[:perms][:init|uninit|volatile]>  another region (RAM, MMIO), repeatable\n"
        "  --ghidra     Ghidra install root (default: $GHIDRA_INSTALL_DIR, ~/.config/revkit/revkit.conf,\n"
        "               the bundled specs, ~/ghidra*, /opt/ghidra*; docs/getting-started.md)\n"
        "  --version    print the version and exit\n";
}

std::optional<unsigned long long> parse_hex(const char *s) {
  try {
    std::size_t used = 0;
    unsigned long long v = std::stoull(s, &used, 16);
    if (s[used] != '\0') return std::nullopt;
    return v;
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options opt;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (arg == "--help" || arg == "-h") return std::nullopt;
    if (arg == "--ghidra" && (v = value())) opt.ghidra_root = v;
    else if (arg == "--lang" && (v = value())) opt.language = v;
    else if (arg == "--file" && (v = value())) opt.file = v;
    else if (arg == "--symbol" && (v = value())) opt.symbol = v;
    else if (arg == "--raw") opt.raw = true;
    else if (arg == "--file-base") opt.file_base = true;
    else if ((arg == "--raw-offset" || arg == "--raw-length") && (v = value())) {
      auto n = parse_hex(v);
      if (!n) {
        std::cerr << "rk-decomp: bad hex value for " << arg << ": " << v << "\n";
        return std::nullopt;
      }
      (arg == "--raw-offset" ? opt.raw_options.offset : opt.raw_options.length.emplace()) = *n;
      opt.raw_layout = true;
    } else if (arg == "--raw-perms" && (v = value())) {
      std::string_view p = v;
      if (p.size() != 3) {
        std::cerr << "rk-decomp: bad --raw-perms: " << v << "\n";
        return std::nullopt;
      }
      opt.raw_options.perms = {p[0] == 'r', p[1] == 'w', p[2] == 'x'};
      opt.raw_layout = true;
    } else if (arg == "--raw-space" && (v = value())) {
      opt.raw_options.space = v;
      opt.raw_layout = true;
    } else if (arg == "--raw-format" && (v = value())) {
      auto c = revkit::loader::raw_container_from_string(v);
      if (!c) {
        std::cerr << "rk-decomp: bad --raw-format: " << v << "\n";
        return std::nullopt;
      }
      opt.raw_options.container = *c;
      opt.raw_layout = true;
    } else if (arg == "--region" && (v = value())) {
      try {
        opt.raw_options.regions.push_back(revkit::loader::parse_raw_region(v));
      } catch (const revkit::loader::LoadError &e) {
        std::cerr << "rk-decomp: " << e.what() << "\n";
        return std::nullopt;
      }
      opt.raw_layout = true;
    } else if ((arg == "--addr" || arg == "--base") && (v = value())) {
      auto n = parse_hex(v);
      if (!n) {
        std::cerr << "rk-decomp: bad hex value for " << arg << ": " << v << "\n";
        return std::nullopt;
      }
      (arg == "--addr" ? opt.addr : opt.base) = n;
    } else {
      std::cerr << "rk-decomp: bad argument: " << arg << "\n";
      return std::nullopt;
    }
  }
  if (opt.file.empty() || (!opt.addr && !opt.symbol)) return std::nullopt;
  if (opt.addr && opt.symbol) {
    std::cerr << "rk-decomp: give --addr or --symbol, not both\n";
    return std::nullopt;
  }
  if (opt.raw && opt.base) opt.raw_layout = true;
  if (opt.raw_layout) {
    opt.raw = true;
    opt.raw_options.base = opt.base.value_or(0);
  }
  return opt;
}

// ELF and PE files are loaded; anything else is a raw image.
bool looks_like_executable(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  char magic[4] = {};
  in.read(magic, sizeof magic);
  std::streamsize n = in.gcount();
  if (n >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') return true;
  return n >= 2 && magic[0] == 'M' && magic[1] == 'Z';
}

int decompile(ghidra::Architecture &arch, unsigned long long addr) {
  using namespace ghidra;

  AddrSpace *code = arch.getDefaultCodeSpace();
  Address entry(code, addr);
  Funcdata *fd = arch.symboltab->getGlobalScope()->queryFunction(entry);
  if (fd == nullptr) {
    std::string name;
    arch.nameFunction(entry, name);
    fd = arch.symboltab->getGlobalScope()->addFunction(entry, name)->getFunction();
  }

  // Discover the function body, then run the full decompiler action pipeline.
  fd->followFlow(Address(code, 0), Address(code, code->getHighest()));
  Action *pipeline = arch.allacts.getCurrent();
  pipeline->reset(*fd);
  if (pipeline->perform(*fd) < 0) {
    std::cerr << "rk-decomp: decompilation stopped early\n";
    return 1;
  }

  arch.print->setOutputStream(&std::cout);
  arch.print->docFunction(fd);
  return 0;
}

int decompile_raw(const Options &opt) {
  if (opt.symbol) {
    std::cerr << "rk-decomp: --symbol needs an ELF or PE file\n";
    return 2;
  }
  if (opt.raw_layout) {
    // revkit's raw loader: the same image rk-lift --raw and the daemon see.
    revkit::loader::RawOptions raw = opt.raw_options;
    raw.language = opt.language.value_or(kDefaultRawLanguage);
    auto image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_raw_file(opt.file, raw));
    revkit::lift::ImageArchitecture arch(image, opt.file, raw.language, &std::cerr);
    arch.init_image();
    return decompile(arch, *opt.addr);
  }
  ghidra::RawBinaryArchitecture arch(opt.file, opt.language.value_or(kDefaultRawLanguage), &std::cerr);
  ghidra::DocumentStorage store;
  arch.init(store);
  return decompile(arch, *opt.addr);
}

int decompile_image(const Options &opt) {
  revkit::loader::LoadOptions load_opts;
  load_opts.image_base = opt.base;
  load_opts.ghidra_image_base = !opt.file_base;
  auto image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(opt.file, load_opts));

  std::string language;
  if (opt.language) {
    language = *opt.language;
  } else if (auto guess = revkit::loader::guess_language(*image)) {
    language = guess->id();
  } else {
    std::cerr << "rk-decomp: no Ghidra language for machine " << image->machine << "; use --lang\n";
    return 1;
  }

  unsigned long long addr = 0;
  if (opt.symbol) {
    auto f = revkit::lift::find_function(*image, *opt.symbol);
    if (!f) {
      std::cerr << "rk-decomp: no function symbol named " << *opt.symbol << "\n";
      return 1;
    }
    addr = f->entry;
  } else {
    addr = *opt.addr;
  }

  revkit::lift::ImageArchitecture arch(image, opt.file, language, &std::cerr);
  arch.init_image();
  return decompile(arch, addr);
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-decomp")) return 0;
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  auto ghidra = revkit::runtime::find_ghidra(opt->ghidra_root, "rk-decomp");
  if (!ghidra) return 1;
  opt->ghidra_root = ghidra->string();

  int rc = 1;
  try {
    revkit::lift::initialize(opt->ghidra_root);
    if (!opt->raw && looks_like_executable(opt->file)) rc = decompile_image(*opt);
    else rc = decompile_raw(*opt);
  } catch (const revkit::loader::LoadError &err) {
    std::cerr << "rk-decomp: " << opt->file << ": " << err.what() << "\n";
  } catch (const revkit::lift::LiftError &err) {
    std::cerr << "rk-decomp: " << err.what() << "\n";
  } catch (const ghidra::LowlevelError &err) {
    std::cerr << "rk-decomp: " << err.explain << "\n";
  } catch (const ghidra::DecoderError &err) {
    std::cerr << "rk-decomp: " << err.explain << "\n";
  }
  ghidra::shutdownDecompilerLibrary();
  return rc;
}
