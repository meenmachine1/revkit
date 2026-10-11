#!/usr/bin/env python3
"""Build the firmware corpus. Runs inside the toolchain container
(corpus/firmware/docker/Dockerfile); scripts/build-firmware-corpus.sh is the
host-side wrapper.

  build.py --corpus /src --cache /cache --out /out [--only GLOB] [-j N]

Reads firmware.json and builds every image: U-Boot for a board, or fwkit
(src/fwkit: FreeRTOS, lwIP, littlefs, Monocypher, heatshrink, printf) for a
target processor. Each image gives, under <out>/<arch>/:

  <name>.bin         the raw image: the ELF's loaded segments at their load
                     addresses, from the lowest (objcopy -O binary's layout)
  <name>.elf         the ELF, with DWARF
  <name>.truth.json  functions from the ELF's DWARF (and its symbol table)
                     inside the raw image: the ground truth

and <out>/manifest.json lists them with their load address, entry point,
language and memory regions (what both revkit and Ghidra are told).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

BUILD = "/build"
HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(cmd: list[str], cwd: str, env=None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise RuntimeError("command failed in %s:\n  %s\n%s" % (cwd, " ".join(cmd), proc.stdout[-6000:]))
    return proc.stdout


def cache_name(ext: dict) -> str:
    return ext.get("file") or os.path.basename(ext["url"])


def unpack(archive: str, dest: str, strip: int) -> None:
    os.makedirs(dest, exist_ok=True)
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                parts = info.filename.split("/")[strip:]
                if not parts or not parts[-1] or info.is_dir():
                    continue
                target = os.path.join(dest, *parts)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                if info.external_attr >> 16 & 0o111:
                    os.chmod(target, 0o755)
        return
    # GNU tar strips hard link targets too (the Xtensa toolchain has them).
    run(["tar", "-xf", archive, "-C", dest, "--strip-components=%d" % strip, "--no-same-owner"], cwd=dest)


def prepare_externals(corpus: str, cache: str, defn: dict) -> dict:
    """Unpacks (and patches) every external under /build/src/<name>; returns
    their origins."""
    origins = {}
    for name, ext in sorted(defn["externals"].items()):
        archive = os.path.join(cache, cache_name(ext))
        digest = sha256_file(archive)
        if digest != ext["sha256"]:
            raise RuntimeError("%s: sha256 %s, expected %s" % (archive, digest, ext["sha256"]))
        root = os.path.join(BUILD, "src", name)
        shutil.rmtree(root, ignore_errors=True)
        unpack(archive, root, ext.get("strip_components", 0))
        origins[name] = {"url": ext["url"], "sha256": ext["sha256"], "license": ext.get("license", "")}
        for rel in ext.get("patches", []):
            patch = os.path.join(corpus, rel)
            run(["patch", "-p1", "-s", "-i", patch], cwd=root)
            origins[name].setdefault("patches", {})[rel] = sha256_file(patch)
    return origins


# --------------------------------------------------------------------------
# The raw image and the truth, from an ELF

def raw_and_truth(elf_path: str, raw_path: str, truth_path: str, max_paddr: int | None = None,
                  min_paddr: int | None = None) -> dict:
    """`max_paddr`: only segments loaded below it make the image (AVR: the
    flash below 0x800000, not the SRAM, EEPROM and fuses above);
    `min_paddr`: the image starts there at the earliest (the MSP430's
    flash, not the ELF headers the linker loads below it)."""
    from elftools.elf.elffile import ELFFile

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_filesz"] > 0 and
                 (max_paddr is None or s["p_paddr"] < max_paddr)]
        base = min(s["p_paddr"] for s in loads)
        if min_paddr is not None:
            base = max(base, min_paddr)
        end = max(s["p_paddr"] + s["p_filesz"] for s in loads)
        entry = elf.header["e_entry"]
        thumb = elf.header["e_machine"] == "EM_ARM" and entry & 1
        entry &= ~1 if thumb else ~0
        functions = dwarf_functions(elf)
        symbols = []
        symtab = elf.get_section_by_name(".symtab")
        for sym in symtab.iter_symbols() if symtab else ():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] != "SHN_UNDEF":
                a = sym["st_value"] & (~1 if elf.header["e_machine"] == "EM_ARM" else ~0)
                symbols.append((a, sym.name))
        # The segments' file bytes at their load addresses, gaps zero: what
        # objcopy -O binary writes for the loaded sections.
        image = bytearray(end - base)
        for seg in loads:
            data = seg.data()[:seg["p_filesz"]]
            at = seg["p_paddr"]
            if at < base:  # cropped by min_paddr
                data = data[base - at:]
                at = base
            image[at - base:at - base + len(data)] = data
    size = len(image)
    if size > 16 << 20:
        raise RuntimeError("%s: raw image is %d bytes (a gap between segments?)" % (elf_path, size))
    with open(raw_path, "wb") as f:
        f.write(image)
    inside = lambda a: base <= a < base + size
    truth = {
        "base": "0x%x" % base,
        "size": size,
        "dwarf_functions": [{"address": "0x%x" % a, "name": n} for a, n in sorted({(a, n) for a, n, _ in functions})
                            if inside(a)],
        # Functions DWARF says never return (DW_AT_noreturn): what settles a
        # disagreement about a callee's no-return.
        "dwarf_noreturn": sorted({"0x%x" % a for a, _, nr in functions if nr and inside(a)}),
        "symbol_functions": [{"address": "0x%x" % a, "name": n} for a, n in sorted(set(symbols)) if inside(a)],
    }
    with open(truth_path, "w") as f:
        json.dump(truth, f, indent=0, sort_keys=True)
        f.write("\n")
    return {"base": base, "size": size, "entry": entry, "dwarf_functions": len(truth["dwarf_functions"]),
            "symbol_functions": len(truth["symbol_functions"])}


def dwarf_functions(elf) -> list[tuple[int, str, bool]]:
    """Every subprogram with code of its own (DW_AT_low_pc, or ranges):
    (address, name, noreturn)."""
    if not elf.has_dwarf_info():
        return []
    # A linked executable's DWARF already holds final addresses; U-Boot
    # keeps its relocations (--emit-relocs), which would add them twice.
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=elf["e_type"] != "ET_EXEC")
    out = []
    thumb_mask = ~1 if elf.header["e_machine"] == "EM_ARM" else ~0
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            attrs = die.attributes
            if "DW_AT_declaration" in attrs:
                continue
            low = None
            if "DW_AT_low_pc" in attrs:
                low = attrs["DW_AT_low_pc"].value
            elif "DW_AT_ranges" in attrs:
                ranges = dwarf.range_lists()
                if ranges is not None:
                    try:
                        rl = ranges.get_range_list_at_offset(attrs["DW_AT_ranges"].value, cu=cu)
                        starts = [r.begin_offset for r in rl if hasattr(r, "begin_offset")]
                        low = min(starts) if starts else None
                    except Exception:
                        low = None
            # Code --gc-sections dropped keeps its DWARF with low_pc 0.
            if not low:
                continue
            name = None
            d = die
            for _ in range(3):
                if "DW_AT_name" in d.attributes:
                    name = d.attributes["DW_AT_name"].value.decode()
                    break
                ref = d.attributes.get("DW_AT_abstract_origin") or d.attributes.get("DW_AT_specification")
                if ref is None:
                    break
                d = d.get_DIE_from_attribute(ref.name)
            out.append((low & thumb_mask, name or "", "DW_AT_noreturn" in attrs or _noreturn_origin(die)))
    return out


def _noreturn_origin(die) -> bool:
    """Whether the declaration a concrete subprogram refers to is noreturn."""
    for attr in ("DW_AT_specification", "DW_AT_abstract_origin"):
        if attr in die.attributes:
            try:
                if "DW_AT_noreturn" in die.get_DIE_from_attribute(attr).attributes:
                    return True
            except Exception:
                pass
    return False


# --------------------------------------------------------------------------
# fwkit

FWKIT_COMMON = ["-ffreestanding", "-fno-builtin-printf", "-fno-pie", "-ffunction-sections", "-fdata-sections",
                "-fno-common", "-w", "-g"]


def fwkit_sources(target: dict) -> list[tuple[str, str]]:
    """(root, relative path) of every source fwkit compiles for a target."""
    src = os.path.join(BUILD, "src")
    fw = os.path.join(src, "fwkit")
    out = [(fw, p) for p in ("main.c", "board.c", "libc/string.c", "libc/stdlib.c")]
    out.append((fw, "arch/" + target["start"]))
    out += [(fw, p) for p in target.get("extra_srcs", [])]
    rtos = os.path.join(src, "freertos-kernel")
    out += [(rtos, p) for p in ("tasks.c", "queue.c", "list.c", "timers.c", "event_groups.c", "stream_buffer.c",
                                "portable/MemMang/heap_4.c")]
    if target.get("freertos_port"):
        out.append((rtos, "portable/%s/port.c" % target["freertos_port"]))
    else:
        out.append((fw, "port/port.c"))
    lwip = os.path.join(src, "lwip")
    for pattern in ("src/core/*.c", "src/core/ipv4/*.c", "src/netif/ethernet.c", "src/apps/sntp/sntp.c",
                    "src/apps/mqtt/mqtt.c"):
        out += [(lwip, p) for p in sorted(glob.glob(pattern, root_dir=lwip))]
    out.append((os.path.join(src, "littlefs"), "lfs.c"))
    out.append((os.path.join(src, "littlefs"), "lfs_util.c"))
    out.append((os.path.join(src, "monocypher"), "src/monocypher.c"))
    out += [(os.path.join(src, "heatshrink"), p) for p in ("heatshrink_encoder.c", "heatshrink_decoder.c")]
    out.append((os.path.join(src, "printf"), "printf.c"))
    return out


def build_fwkit(out: str, image: dict, target: dict, jobs: int) -> dict:
    src = os.path.join(BUILD, "src")
    fw = os.path.join(src, "fwkit")
    cc = os.path.join(BUILD, "src", target["cc"]) if "/" in target["cc"] else target["cc"]
    rtos = os.path.join(src, "freertos-kernel")
    port = os.path.join(rtos, "portable", target["freertos_port"]) if target.get("freertos_port") else \
        os.path.join(fw, "port")
    includes = [fw, os.path.join(fw, "libc", "include"), os.path.join(fw, "lwip"), os.path.join(rtos, "include"),
                port, os.path.join(src, "lwip", "src", "include"), os.path.join(src, "littlefs"),
                os.path.join(src, "monocypher", "src"), os.path.join(src, "heatshrink"), os.path.join(src, "printf")]
    defines = ["-DBOARD_MMIO=%sUL" % target["mmio"], '-DBOARD_NAME="%s"' % image["name"].split("/")[-1],
               "-DLFS_NO_MALLOC", "-DLFS_NO_DEBUG", "-DLFS_NO_WARN", "-DHEATSHRINK_DYNAMIC_ALLOC=0",
               "-DPRINTF_DISABLE_SUPPORT_FLOAT", "-DPRINTF_DISABLE_SUPPORT_EXPONENTIAL"]
    if not target.get("freertos_port"):
        defines.append("-DFWKIT_GENERIC_PORT")
    # Only the compiler's own headers and fwkit's libc: a Debian cross
    # compiler also searches the host's /usr/include.
    gcc_include = run([cc] + target["cflags"] + ["-print-file-name=include"], cwd=fw).strip()
    cflags = ["-" + image["opt"]] + target["cflags"] + FWKIT_COMMON + defines + ["-I" + d for d in includes]
    cflags += ["-nostdinc", "-isystem", gcc_include]
    cflags.append("-ffile-prefix-map=%s=." % src)
    objdir = os.path.join(BUILD, "obj", image["name"])
    os.makedirs(objdir, exist_ok=True)
    objects = []
    for root, rel in fwkit_sources(target):
        obj = os.path.join(objdir, os.path.basename(root) + "__" + rel.replace("/", "__") + ".o")
        extra = ["-fno-tree-loop-distribute-patterns"] if rel.startswith("libc/") else []
        run([cc] + cflags + extra + ["-c", rel, "-o", obj], cwd=root)
        objects.append(obj)
    with open(os.path.join(fw, "arch", "link.ld.in")) as f:
        script = f.read()
    for key in ("rom", "romsize", "ram", "ramsize"):
        script = script.replace("@%s@" % key.upper(), target[key])
    ld = os.path.join(objdir, "link.ld")
    with open(ld, "w") as f:
        f.write(script)
    arch_dir = os.path.join(out, image["name"].split("/")[0])
    os.makedirs(arch_dir, exist_ok=True)
    base = os.path.join(out, image["name"])
    elf = base + ".elf"
    # (TI's MSP430 binutils predate --build-id.)
    build_id = ["-Wl,--build-id=none"] if target.get("build_id", True) else []
    run([cc] + cflags + ["-nostdlib", "-no-pie", "-static", "-T", ld, "-Wl,--gc-sections"] + build_id +
        ["-o", elf] + objects + target.get("ldlibs", ["-lgcc"]), cwd=objdir, env=dict(os.environ, SOURCE_DATE_EPOCH="0"))
    info = raw_and_truth(elf, base + ".bin", base + ".truth.json",
                         min_paddr=target.get("min_paddr") and int(target["min_paddr"], 16))
    info["regions"] = ["ram:%x:%x" % (int(target["ram"], 16), int(target["ramsize"], 16)),
                       "mmio:%x:1000:rw-:volatile" % int(target["mmio"], 16)]
    info["language"] = target["language"]
    info["flags_sha256"] = sha256_json({"cc": target["cc"], "cflags": cflags, "ld": script})
    info["project"] = "fwkit"
    info["opt"] = image["opt"]
    return info


# --------------------------------------------------------------------------
# mcukit (src/mcukit, 8- and 16-bit MCUs) and grbl (AVR)

MCUKIT_COMMON = ["-ffreestanding", "-ffunction-sections", "-fdata-sections", "-w", "-g"]


def gcc_mcu(out: str, image: dict, target: dict, sources: list[tuple[str, str]], defines: list[str],
            includes: list[str]) -> tuple[str, dict]:
    """Compiles and links an MCU image with a GCC (avr-gcc, msp430-elf-gcc):
    avr-libc's startup and linker script when the target says "ldscript":
    "default", else the target's own script without the C library."""
    cc = os.path.join(BUILD, "src", target["cc"]) if "/" in target["cc"] else target["cc"]
    cflags = ["-" + image["opt"]] + target["cflags"] + MCUKIT_COMMON + defines + ["-I" + d for d in includes]
    cflags.append("-ffile-prefix-map=%s=." % os.path.join(BUILD, "src"))
    objdir = os.path.join(BUILD, "obj", image["name"])
    os.makedirs(objdir, exist_ok=True)
    objects = []
    for root, rel in sources:
        obj = os.path.join(objdir, os.path.basename(root) + "__" + rel.replace("/", "__") + ".o")
        run([cc] + cflags + ["-c", rel, "-o", obj], cwd=root)
        objects.append(obj)
    os.makedirs(os.path.join(out, image["name"].split("/")[0]), exist_ok=True)
    elf = os.path.join(out, image["name"]) + ".elf"
    link = [cc] + cflags + ["-Wl,--gc-sections", "-o", elf] + objects
    script = ""
    if target.get("ldscript", "default") != "default":
        with open(os.path.join(BUILD, "src", target["ldscript"])) as f:
            script = f.read()
        ld = os.path.join(objdir, "link.ld")
        with open(ld, "w") as f:
            f.write(script)
        link = [cc] + cflags + ["-nostdlib", "-nostartfiles", "-T", ld, "-Wl,--gc-sections", "-o", elf] + objects + \
            target.get("ldlibs", ["-lgcc"])
    run(link, cwd=objdir, env=dict(os.environ, SOURCE_DATE_EPOCH="0"))
    return elf, {"cc": target["cc"], "cflags": cflags, "ld": script}


def build_mcukit(out: str, image: dict, target: dict) -> dict:
    src = os.path.join(BUILD, "src")
    kit = os.path.join(src, "mcukit")
    base = os.path.join(out, image["name"])
    if target.get("family") == "sdcc":
        return build_sdcc(out, image, target, [(kit, "main.c"), (kit, "arch/" + target["arch"])])
    elf, flags = gcc_mcu(out, image, target, [(kit, "main.c"), (kit, "arch/" + target["arch"])], [], [kit])
    info = raw_and_truth(elf, base + ".bin", base + ".truth.json", target.get("max_paddr") and int(target["max_paddr"], 16),
                         target.get("min_paddr") and int(target["min_paddr"], 16))
    info.update(regions=target.get("regions", []), language=target["language"], flags_sha256=sha256_json(flags),
                project="mcukit", opt=image["opt"])
    return info


def build_grbl(out: str, image: dict, target: dict) -> dict:
    """grbl 1.1h (a CNC controller, the firmware of countless AVR boards)
    as its Makefile builds it: every grbl/*.c, avr-libc."""
    root = os.path.join(BUILD, "src", "grbl")
    sources = [(root, os.path.join("grbl", f)) for f in sorted(os.listdir(os.path.join(root, "grbl"))) if f.endswith(".c")]
    elf, flags = gcc_mcu(out, image, target, sources, ["-DF_CPU=16000000L", "-DBAUD_RATE=115200"],
                         [os.path.join(root, "grbl")])
    base = os.path.join(out, image["name"])
    info = raw_and_truth(elf, base + ".bin", base + ".truth.json", target.get("max_paddr") and int(target["max_paddr"], 16))
    info.update(regions=target.get("regions", []), language=target["language"], flags_sha256=sha256_json(flags),
                project="grbl", opt=image["opt"])
    return info


def build_sdcc(out: str, image: dict, target: dict, sources: list[tuple[str, str]]) -> dict:
    """An SDCC image (8051, Z80): Intel HEX from the linker, the flat image
    from it, and the truth from SDCC's debug records (.cdb: our functions)
    and the linker map (every symbol in code)."""
    objdir = os.path.join(BUILD, "obj", image["name"])
    os.makedirs(objdir, exist_ok=True)
    cflags = ["--opt-code-size" if image["opt"] == "Os" else "--opt-code-speed"] + target["cflags"] + \
        ["--debug", "-I" + os.path.join(BUILD, "src", "mcukit")]
    rels = []
    for root, rel in sources:
        obj = os.path.join(objdir, os.path.basename(rel).replace(".c", ".rel"))
        run(["sdcc"] + cflags + ["-c", os.path.join(root, rel), "-o", obj], cwd=objdir)
        rels.append(obj)
    ihx = os.path.join(objdir, "image.ihx")
    run(["sdcc"] + cflags + target.get("ldflags", []) + ["-o", ihx] + rels, cwd=objdir,
        env=dict(os.environ, SOURCE_DATE_EPOCH="0"))
    os.makedirs(os.path.join(out, image["name"].split("/")[0]), exist_ok=True)
    base = os.path.join(out, image["name"])
    shutil.copyfile(ihx, base + ".ihx")
    # The flat image from the HEX records, gaps zero, from address 0.
    image_bytes = bytearray()
    upper = 0
    entry = 0
    with open(ihx) as f:
        for line in f:
            line = line.strip()
            if not line.startswith(":"):
                continue
            rec = bytes.fromhex(line[1:])
            n, addr, kind, data = rec[0], rec[1] << 8 | rec[2], rec[3], rec[4:4 + rec[0]]
            if kind == 0:
                at = upper + addr
                if len(image_bytes) < at + n:
                    image_bytes.extend(b"\0" * (at + n - len(image_bytes)))
                image_bytes[at:at + n] = data
            elif kind == 4:
                upper = (data[0] << 8 | data[1]) << 16
    with open(base + ".bin", "wb") as f:
        f.write(image_bytes)
    # .cdb: F: records name functions, L: records give their addresses
    # (L:XG$f$... is a function's end).
    cdb_names = set()
    cdb_addr = {}
    for path in sorted(glob.glob(os.path.join(objdir, "*.cdb"))):
        with open(path) as f:
            for line in f:
                # (A record's key is scope$name$level$block; F: and L: spell
                # the levels differently: G$crc16$0_0$0, G$crc16$0$0.)
                if line.startswith("F:"):
                    cdb_names.add("$".join(line[2:].split("(")[0].split("$")[:2]))
                elif line.startswith("L:") and not line.startswith("L:X") and not line.startswith("L:A"):
                    key, _, value = line[2:].strip().rpartition(":")
                    try:
                        cdb_addr["$".join(key.split("$")[:2])] = int(value, 16)
                    except ValueError:
                        pass
    functions = sorted({(cdb_addr[k], k.split("$")[1]) for k in cdb_names if k in cdb_addr})
    # The linker map: symbols in code areas (not constants).
    symbols = set()
    area = ""
    with open(os.path.join(objdir, "image.map")) as f:
        for line in f:
            m = re.match(r"^Area\s+", line)
            if m:
                area = ""
                continue
            m = re.match(r"^(\S+)\s+[0-9A-Fa-f]{4,8}\s+[0-9A-Fa-f]{4,8}\s+=", line)
            if m:
                area = m.group(1)
                continue
            m = re.match(r"^\s+C:\s+([0-9A-Fa-f]+)\s+(\S+)", line) or \
                re.match(r"^\s+([0-9A-Fa-f]{8})\s+(_\S+)", line)
            if m and area not in ("CONST", "XINIT", "INITIALIZER", "DATA", "BSS", "XSEG", "PSEG", "ISEG", "IABS",
                                  "XABS", "BSEG", "OSEG", "DABS", "HEADER0"):
                symbols.add((int(m.group(1), 16), m.group(2).lstrip("_")))
    size = len(image_bytes)
    inside = lambda a: 0 <= a < size
    truth = {
        "base": "0x0",
        "size": size,
        "dwarf_functions": [{"address": "0x%x" % a, "name": n} for a, n in functions if inside(a)],
        "dwarf_noreturn": [],
        "symbol_functions": [{"address": "0x%x" % a, "name": n} for a, n in sorted(symbols) if inside(a)],
        "truth_source": "sdcc .cdb and .map",
    }
    with open(base + ".truth.json", "w") as f:
        json.dump(truth, f, indent=0, sort_keys=True)
        f.write("\n")
    # The ELF slot of the manifest holds the HEX file the image came from.
    shutil.copyfile(ihx, base + ".elf")
    return {"base": 0, "size": size, "entry": entry, "dwarf_functions": len(truth["dwarf_functions"]),
            "symbol_functions": len(truth["symbol_functions"]), "regions": target.get("regions", []),
            "language": target["language"], "flags_sha256": sha256_json({"cflags": cflags, "ldflags": target.get("ldflags", [])}),
            "project": "mcukit", "opt": image["opt"]}


# --------------------------------------------------------------------------
# U-Boot

def build_uboot(out: str, image: dict, jobs: int) -> dict:
    src = os.path.join(BUILD, "src", "u-boot")
    board = image["defconfig"].replace("_defconfig", "")
    objdir = os.path.join(BUILD, "obj", "u-boot", board)
    os.makedirs(objdir, exist_ok=True)
    env = dict(os.environ, SOURCE_DATE_EPOCH="0", KBUILD_BUILD_USER="revkit", KBUILD_BUILD_HOST="corpus",
               KBUILD_BUILD_TIMESTAMP="1970-01-01", LC_ALL="C")
    make = ["make", "-s", "O=" + objdir, "CROSS_COMPILE=" + image["cross"], "NO_PYTHON=1"]
    run(make + [image["defconfig"]], cwd=src, env=env)
    run(make + ["-j%d" % jobs, "u-boot", "u-boot.bin"] + image.get("make_args", []), cwd=src, env=env)
    arch_dir = os.path.join(out, image["name"].split("/")[0])
    os.makedirs(arch_dir, exist_ok=True)
    base = os.path.join(out, image["name"])
    shutil.copyfile(os.path.join(objdir, "u-boot"), base + ".elf")
    info = raw_and_truth(base + ".elf", base + ".bin", base + ".truth.json")
    info["regions"] = image.get("regions", [])
    info["language"] = image["language"]
    with open(os.path.join(objdir, ".config")) as f:
        config = f.read()
    info["flags_sha256"] = sha256_json({"cross": image["cross"], "config": config})
    info["project"] = "u-boot"
    info["board"] = board
    return info


# --------------------------------------------------------------------------

def tool_version(cmd: str) -> str:
    try:
        out = subprocess.run([cmd, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
    except OSError:
        return "?"
    return out.splitlines()[0].strip() if out else "?"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="/src", help="corpus/firmware (recipes)")
    ap.add_argument("--cache", default="/cache", help="downloaded external archives")
    ap.add_argument("--out", default="/out")
    ap.add_argument("--only", action="append", default=[], metavar="GLOB", help="build only images matching GLOB")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4)
    args = ap.parse_args(argv)

    with open(os.path.join(args.corpus, "firmware.json")) as f:
        defn = json.load(f)
    origins = prepare_externals(args.corpus, args.cache, defn)
    fwkit_root = os.path.join(BUILD, "src", "fwkit")
    shutil.rmtree(fwkit_root, ignore_errors=True)
    shutil.copytree(os.path.join(args.corpus, "src", "fwkit"), fwkit_root)
    inputs = {}
    for dirpath, _dirs, files in os.walk(fwkit_root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            inputs[os.path.relpath(full, fwkit_root)] = sha256_file(full)
    origins["fwkit"] = {"path": "corpus/firmware/src/fwkit", "inputs": dict(sorted(inputs.items()))}
    mcukit_root = os.path.join(BUILD, "src", "mcukit")
    shutil.rmtree(mcukit_root, ignore_errors=True)
    shutil.copytree(os.path.join(args.corpus, "src", "mcukit"), mcukit_root)
    inputs = {}
    for dirpath, _dirs, files in os.walk(mcukit_root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            inputs[os.path.relpath(full, mcukit_root)] = sha256_file(full)
    origins["mcukit"] = {"path": "corpus/firmware/src/mcukit", "inputs": dict(sorted(inputs.items()))}

    images = [im for im in defn["images"] if not args.only or any(fnmatch.fnmatch(im["name"], p) for p in args.only)]
    # U-Boot builds are parallel inside; run a few images at a time.
    per = max(1, args.jobs // 4)
    entries, failures = [], []

    def one(image):
        if image["kind"] == "uboot":
            info = build_uboot(args.out, image, per)
            info["source_sha256"] = sha256_json(origins["u-boot"])
        elif image["kind"] in ("mcukit", "grbl"):
            target = defn["targets"][image["target"]]
            if image["kind"] == "grbl":
                info = build_grbl(args.out, image, target)
                info["source_sha256"] = sha256_json(origins["grbl"])
            else:
                info = build_mcukit(args.out, image, target)
                info["source_sha256"] = sha256_json(origins["mcukit"]["inputs"])
            info["target"] = image["target"]
        else:
            target = defn["targets"][image["target"]]
            info = build_fwkit(args.out, image, target, per)
            info["source_sha256"] = sha256_json({k: origins[k].get("sha256") or origins[k].get("inputs")
                                                 for k in ("fwkit", "freertos-kernel", "lwip", "littlefs",
                                                           "monocypher", "heatshrink", "printf")})
            info["target"] = image["target"]
        name = image["name"]
        entry = {
            "name": name,
            "arch": name.split("/")[0],
            "path": name + ".bin",
            "elf": name + ".elf",
            "truth": name + ".truth.json",
            "language": info["language"],
            "base": "0x%x" % info["base"],
            "entry": "0x%x" % info["entry"],
            "regions": info["regions"],
            "size": info["size"],
            "sha256": sha256_file(os.path.join(args.out, name + ".bin")),
            "elf_sha256": sha256_file(os.path.join(args.out, name + ".elf")),
            "dwarf_functions": info["dwarf_functions"],
            "symbol_functions": info["symbol_functions"],
            "project": info["project"],
            "source_sha256": info["source_sha256"],
            "flags_sha256": info["flags_sha256"],
        }
        for k in ("board", "target", "opt"):
            if k in info:
                entry[k] = info[k]
        return entry

    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        futs = {pool.submit(one, im): im["name"] for im in images}
        for fut in concurrent.futures.as_completed(futs):
            name = futs[fut]
            try:
                entries.append(fut.result())
                print("built %s" % name, flush=True)
            except Exception as e:  # keep going, report at the end
                failures.append("%s: %s" % (name, e))
                print("FAILED %s" % name, flush=True)

    compilers = {}
    for t in sorted({t["cc"] for t in defn["targets"].values() if t.get("family") != "sdcc"} |
                    ({"sdcc"} if any(t.get("family") == "sdcc" for t in defn["targets"].values()) else set()) |
                    {im["cross"] + "gcc" for im in defn["images"] if im["kind"] == "uboot"}):
        compilers[t] = tool_version(os.path.join(BUILD, "src", t) if "/" in t else t)
    manifest = {
        "manifest_version": 1,
        "toolchain": {"image": os.environ.get("RK_CORPUS_IMAGE", ""), "compilers": compilers},
        "sources": origins,
        "images": sorted(entries, key=lambda e: e["name"]),
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    print("%d images, %d failed" % (len(entries), len(failures)))
    for msg in failures:
        print(msg, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
