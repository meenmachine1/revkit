"""Raw layout detection through the SDK (api_minor 23, feature "raw-detect"):
what a file with no header is refused for, a raw ARM firmware's suggestion
with its confidence, evidence and tie group, a language hint pinning the
answer, the suggestion's options importing as they are, progress and
stopping it. The MCP tool is in test_mcp_tools.py."""

import os
import shutil
import subprocess
import threading
from pathlib import Path

import grpc
import pytest

from revkit import Client, Daemon, InvalidArgument, NotFound, RevkitError, detect_confidence, format_memory_region, memory_region
from revkit.v1 import project_pb2

ROOT = Path(__file__).resolve().parents[3]
ARMFW = ROOT / "src" / "analysis" / "tests" / "fixtures" / "armfw"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def firmware(tmp_path_factory):
    """armfw scaled up with generated functions (about 250 KB of ARM code), and as built (1 KB)."""
    tools = [shutil.which(t) for t in ("clang", "ld.lld", "llvm-objcopy")]
    if not all(tools):
        pytest.skip("needs clang, ld.lld and llvm-objcopy")
    out = tmp_path_factory.mktemp("detect-armfw")
    subprocess.run(["sh", str(ARMFW / "build.sh"), *tools, str(out / "bulk"), "-O2", "1500"], check=True, capture_output=True)
    subprocess.run(["sh", str(ARMFW / "build.sh"), *tools, str(out / "small")], check=True, capture_output=True)
    return out


def test_refuses_what_is_no_program(image_daemon, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "raw-detect" in info.features and info.api_minor >= 23
        noise = os.urandom(1 << 16)
        r = rk.detect_raw_layout("default", content=noise)
        assert r.HasField("refusal") and r.refusal.reason == "high-entropy" and r.refusal.detail
        assert not r.suggestions
        assert [(s.offset, s.size, s.kind) for s in r.segments] == [(0, 1 << 16, project_pb2.RAW_SEGMENT_KIND_HIGH_ENTROPY)]
        assert r.file_size == 1 << 16

        # By path, as an import reads one; with progress, which ends done.
        (tmp_path / "log.txt").write_bytes(b"log line: sensor ok\r\n" * 4096)
        seen = []
        r = rk.detect_raw_layout("default", path=str(tmp_path / "log.txt"), progress=seen.append, poll=0.005)
        assert r.refusal.reason == "not-code"
        assert seen and seen[-1].done and seen[-1].progress == 1.0 and not seen[-1].error
        assert seen[-1].phase == project_pb2.RAW_DETECT_PHASE_DONE and "not-code" in seen[-1].message
        assert rk.detect_raw_layout("default", content=b"\x12" * 16).refusal.reason == "too-small"
        # Nothing was imported.
        assert not rk.programs("default")

        with pytest.raises(NotFound):
            rk.detect_raw_layout("default", path=str(tmp_path / "missing"))
        with pytest.raises(NotFound):
            rk.detect_raw_layout("no-such-project", content=noise)
        with pytest.raises(InvalidArgument):
            rk.detect_raw_layout("default", content=noise, language_id="NOPE:LE:32:x")
        with pytest.raises(InvalidArgument):
            rk.detect_raw_layout("default", content=noise, processor="no such processor")


def test_suggests_a_raw_arm_firmware_and_the_suggestion_imports(image_daemon, firmware):
    fw = firmware / "bulk" / "fw.bin"
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        # Knowing the processor only: the family, with the variants it can't tell apart.
        seen = []
        r = rk.detect_raw_layout("default", path=str(fw), processor="arm", progress=seen.append, poll=0.01)
        assert not r.HasField("refusal"), r.refusal
        top = r.suggestions[0]
        assert top.options.format == "raw"
        assert top.options.language_id.startswith("ARM:LE:32:"), top.options
        assert top.options.compiler_spec_id == "default"
        assert top.options.raw_offset == 0
        assert detect_confidence(top.processor_confidence) in ("medium", "high")
        assert detect_confidence(top.variant_confidence) and detect_confidence(top.base_confidence)
        # armfw is ARMv4T code: the variant named, or among those the evidence can't tell apart.
        assert top.options.language_id == "ARM:LE:32:v4t" or any(t.startswith("ARM:LE:32:v4t:") for t in top.tie_group), \
            (top.options.language_id, list(top.tie_group))
        assert not top.language_pinned
        about = {e.about for e in top.evidence}
        assert "processor" in about and all(e.text for e in top.evidence)
        assert "instructions decode" in top.evidence[0].text
        assert sum(s.size for s in r.segments) == r.file_size == fw.stat().st_size
        assert r.elapsed_seconds > 0
        # The progress: phases in order, a fraction that never goes back, candidates counted.
        assert seen and seen[-1].done and seen[-1].progress == 1.0
        assert [p.phase for p in seen] == sorted(p.phase for p in seen)
        fractions = [p.progress for p in seen if p.progress >= 0]
        assert fractions == sorted(fractions)
        assert seen[-1].candidates_total >= 2 and seen[-1].candidates_done == seen[-1].candidates_total
        assert seen[-1].message.startswith("Detected ARM:LE:32:")

        # Knowing the language: the suggestion names it, and imports as it is.
        r = rk.detect_raw_layout("default", content=fw.read_bytes(), language_id="ARM:LE:32:v4t")
        top = r.suggestions[0]
        assert top.language_pinned and top.options.language_id == "ARM:LE:32:v4t"
        assert not any(t.startswith("ARM:LE:32:v4t:") for t in top.tie_group)
        assert not rk.programs("default")
        imported = rk.import_program("default", path=str(firmware / "small" / "fw.bin"), name="detected", options=top.options)
        assert imported.program.format == "raw" and imported.program.language_id == "ARM:LE:32:v4t"

        # Too little code to tell: refused, with its closest guesses to show.
        r = rk.detect_raw_layout("default", path=str(firmware / "small" / "fw.bin"))
        assert r.refusal.reason == "unknown-processor"
        assert r.suggestions and all(detect_confidence(s.processor_confidence) != "high" for s in r.suggestions)


def test_a_detection_is_stopped(image_daemon, firmware):
    """Setting ``cancel`` stops it (CancelRawDetect): the call raises CANCELLED and the progress says so."""
    fw = firmware / "bulk" / "fw.bin"
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        cancel = threading.Event()
        seen = []

        def progress(p):
            seen.append(p)
            if p.candidates_done >= 1:
                cancel.set()

        with pytest.raises(RevkitError) as e:
            rk.detect_raw_layout("default", path=str(fw), progress=progress, cancel=cancel, poll=0.005)
        assert e.value.code == grpc.StatusCode.CANCELLED
        last = seen[-1]
        assert last.done and last.cancelled and not last.error
        assert last.candidates_done < last.candidates_total and last.progress < 1.0
        assert last.message == "Detection cancelled"


def test_memory_regions_round_trip():
    r = memory_region("periph:0x40000000:1000:rw-:volatile")
    assert (r.name, r.start, r.size, r.read, r.write, r.execute, r.is_volatile, r.initialized) == \
        ("periph", 0x40000000, 0x1000, True, True, False, True, False)
    assert format_memory_region(r) == "periph:40000000:1000:rw-:volatile"
    assert format_memory_region(memory_region("rom:0:100:r-x:init")) == "rom:0:100:r-x:init"
    assert format_memory_region(memory_region("ram:20000000:40000")) == "ram:20000000:40000:rw-"
    for bad in ("ram", "ram:zz:10", "ram:0:0", "ram:0:10:rwq", ":0:10"):
        with pytest.raises(ValueError):
            memory_region(bad)


def test_raw_import_options(image_daemon, firmware):
    """import_program's raw_offset and regions (what a suggestion carries), given by hand."""
    fw = firmware / "small" / "fw.bin"
    padded = fw.parent / "with-header.bin"
    padded.write_bytes(b"FWIMAGE v1.2\n".ljust(0x40, b"\xff") + fw.read_bytes())
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        imported = rk.import_program("default", path=str(padded), name="with-header", format="raw",
                                     language_id="ARM:LE:32:v4t:default", image_base=0x8000, raw_offset=0x40,
                                     regions=["ram:20000000:1000", "periph:40000000:100:rw-:volatile"])
        summary = rk.program(imported.program.program_id).summary()
        assert summary.language.language_id == "ARM:LE:32:v4t" and summary.language.compiler_spec_id == "default"
        assert summary.image_base.offset == 0x8000
        # The image without its header at the base, then the regions.
        blocks = [(b.name, b.range.first.offset, b.range.last.offset) for b in summary.memory]
        assert blocks == [("ram", 0x8000, 0x8000 + fw.stat().st_size - 1), ("ram", 0x20000000, 0x20000fff),
                          ("periph", 0x40000000, 0x400000ff)]
