"""revkit.hooklib's handlers over a fake hook (no daemon)."""

from revkit import hooklib


class FakeHook:
    def __init__(self, args, memory):
        self.args = args
        self.memory = memory
        self.written = {}

    def arg(self, i):
        return self.args[i] if i < len(self.args) else 0

    def read_string(self, addr, max_length=4096):
        data = self.memory[addr]
        return data[: data.index(b"\0")] if b"\0" in data else data

    def write_memory(self, addr, data):
        self.written[addr] = data


def test_printf_formats_from_the_arguments():
    out = []
    h = FakeHook([0x1000, 0xFFFFFFFF, 0x2000, ord("x"), 255, 255, 0x7FF0], {0x1000: b"%d %s %c %04x %5u %p%%\0", 0x2000: b"hi\0"})
    n = hooklib.printf(out)(h)
    assert out == [b"-1 hi x 00ff   255 0x7ff0%"]
    assert n == len(out[0])


def test_constants_sequences_and_logs():
    h = FakeHook([1, 2, 3, 4, 5], {})
    assert hooklib.returns(7)(h) == 7
    seq = hooklib.sequence([4, 2])
    assert [seq(h), seq(h), seq(h)] == [4, 2, None]
    log = []
    assert hooklib.record(log, returns=1, args=2)(h) == 1 and log == [(1, 2)]
    assert hooklib.skip(h) == 0


def test_strlen_and_memset():
    h = FakeHook([0x10, 0x41, 3], {0x10: b"abcd\0"})
    assert hooklib.strlen(h) == 4
    assert hooklib.memset(h) == 0x10 and h.written == {0x10: b"AAA"}
