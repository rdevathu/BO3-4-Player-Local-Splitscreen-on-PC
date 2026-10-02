"""Exercise the production Umbra growth and startup gate in an isolated process.

    python tools/test_umbra_prerequisite.py
    python tools/test_umbra_prerequisite.py --image /path/to/game-unpacked.bin

Requires a native C++20 compiler; optional disassembly requires Capstone. No game
is started or changed. Stock operands are reconstructed from the component's
reference table, not claimed to come from a pristine executable.
"""
from pathlib import Path
import argparse
import os
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(text, declaration):
    start = text.index(declaration)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def inspect_image(path, addresses):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    # This leaf setter is straight-line: load object, sign-extend lc, indexed
    # store, return. Replace only its displacement to reconstruct the stock leaf.
    row = re.search(r"\{0x01C8CAFA, 3, (0x\w+),", addresses)
    old = int(row[1], 16)
    with path.open("rb") as image:
        image.seek(0x01C8CAF0)
        code = bytearray(image.read(0x16))
    struct.pack_into("<I", code, 0x0D, old)
    instructions = list(decoder.disasm(code, 0x01C8CAF0))
    assert [i.mnemonic for i in instructions] == ["mov", "movsxd", "mov", "ret"]
    assert "rdx*4 + 0x12dc48" in instructions[2].op_str
    assert old + 2 * 4 == 0x12DC50  # lc 2 aliases persistent selector[0]
    print("Reconstructed stock leaf (input dump may already be patched):")
    for ins in instructions:
        print(f"  {ins.address:08X} {ins.mnemonic} {ins.op_str}")

    # Reconstruct the two-controller mapping walk, using its checked-in stock
    # RIP displacements. This is the predicate path used by Lua to query whether
    # controllers 2/3 have seats; it searches records instead of indexing by ci.
    targets = []
    for rva in (0x020E3045, 0x020E304C):
        match = re.search(r"\{0x%08X, \{([^}]+)\}" % rva, addresses)
        displacement = bytes(int(part, 16) for part in match[1].split(","))
        targets.append(rva + 4 + struct.unpack("<i", displacement)[0])
    assert targets[1] - targets[0] == 2 * 0x24
    # These checked-in count patches reconstruct the unextended Lua constants.
    for rva in (0x01FD6BFD, 0x01FD6C1D):
        assert re.search(r"\{0x%08X, 0x00, 0x80," % rva, addresses)
        with path.open("rb") as image:
            image.seek(rva - 2)
            value = bytearray(image.read(4))
        value[2] = 0
        assert struct.unpack("<f", value)[0] == 2.0
    print("Reconstructed stock Lua controller maxima=2; controller mapping walk=2 records")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path)
    args = parser.parse_args()
    addresses = (ROOT / "src/component/splitscreen_addresses.hpp").read_text()
    growth = (ROOT / "src/component/splitscreen/10_relocations_b.inl").read_text()
    component = (ROOT / "src/component/splitscreen.cpp").read_text(encoding="utf-8-sig")

    tables = addresses[addresses.index("inline constexpr uint32_t umbra_params_new"):
                       addresses.index("inline constexpr lc_gate lensflare_gates")]
    types = addresses[addresses.index("struct umbra_disp"):
                      addresses.index("struct umbra_bound")]
    types += function(addresses, "struct umbra_bound") + ";\n"
    obj = re.search(r"inline constexpr uint32_t umbra_object_rva = 0x\w+;", addresses)[0]
    grow = function(growth, "bool grow_umbra_client_arrays()")

    # Compile the actual startup prefix, ending exactly where the first host
    # mutation begins. The remainder is an observable admission-stage sentinel.
    # An added mutation before the gate must be stubbed explicitly, or fails to
    # compile. post_unpack is also production code, including the retry decision.
    apply = function(component, "bool try_apply()")
    prefix = apply[:apply.index("// Behind ezz BOIII")]
    assert component.count("grow_umbra_client_arrays()") == 1
    assert prefix.index("publish_status_magic();") < prefix.index("if (!ready())")
    startup = prefix + "++extension_stages; return true; }\n"
    post_unpack = function(component, "void post_unpack() override").replace(" override", "")

    harness = r'''
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <vector>
#include <sys/mman.h>
#include "utils/finally.hpp"
using namespace std::chrono_literals;
using DWORD = uint32_t;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_READ = 0x20, PAGE_READONLY = 2;
uint8_t* image;
size_t base() { return reinterpret_cast<size_t>(image); }
bool image_ready = true;
bool raise_local_client_count = true;
bool ready() { return image_ready; }
int status_publications = 0, extension_stages = 0, schedules = 0;
void publish_status_magic() { ++status_publications; }
void note(const char*, ...) {}
namespace game { bool is_server() { return false; } }
namespace scheduler {
enum condition { cond_continue, cond_end };
enum class pipeline { async };
std::function<condition()> pending;
template<class F, class T> void schedule(F f, pipeline, T) { ++schedules; pending = f; }
}
const void* unreadable = nullptr;
bool readable(const void* p, size_t) { return p != unreadable; }
std::map<size_t, DWORD> protections, initial_protections;
int protect_calls = 0, fail_at = 0;
bool VirtualProtect(void* ptr, size_t size, DWORD want, DWORD* old) {
    assert(size <= 4);
    ++protect_calls;
    if (protect_calls == fail_at) return false;
    const size_t page = reinterpret_cast<size_t>(ptr) & ~size_t(0xFFF);
    assert(reinterpret_cast<size_t>(ptr) + size <= page + 0x1000);
    *old = protections.at(page);
    protections[page] = want;
    const int flags = PROT_READ | (want == PAGE_EXECUTE_READWRITE ? PROT_WRITE : 0);
    assert(mprotect(reinterpret_cast<void*>(page), 0x1000, flags) == 0);
    return true;
}
bool umbra_grown = false;
'''
    harness += types + tables + obj + "\n" + grow + startup + post_unpack
    harness += r'''
void reset() {
    for (auto [page, value] : protections)
        assert(mprotect(reinterpret_cast<void*>(page), 0x1000, PROT_READ | PROT_WRITE) == 0);
    protections.clear();
    umbra_grown = false; image_ready = true; unreadable = nullptr; raise_local_client_count = true;
    status_publications = extension_stages = schedules = protect_calls = fail_at = 0;
    scheduler::pending = {};
    *reinterpret_cast<uint64_t*>(image + umbra_object_rva) = 0;
    std::memset(image + 0x01C8C000, 0xCC, 0x4000);
    for (auto s : umbra_disps) std::memcpy(image + s.rva + s.off, &s.old_value, 4);
    for (auto u : umbra_bounds) image[u.rva + 3] = u.old_value;
}
void lock_pages() {
    for (auto s : umbra_disps) protections[(base() + s.rva + s.off) & ~size_t(0xFFF)] = PAGE_EXECUTE_READ;
    for (auto u : umbra_bounds) protections[(base() + u.rva + 3) & ~size_t(0xFFF)] = PAGE_READONLY;
    initial_protections = protections;
    for (auto [page, value] : protections)
        assert(mprotect(reinterpret_cast<void*>(page), 0x1000, PROT_READ) == 0);
}
std::vector<uint8_t> snapshot() { return {image + 0x01C8C000, image + 0x01C90000}; }
void disabled(const std::vector<uint8_t>& before) {
    post_unpack();
    assert(!umbra_grown && !raise_local_client_count && !extension_stages && status_publications == 1 && !schedules);
    assert(snapshot() == before);
    assert(protections == initial_protections);
}
int main() {
    image = static_cast<uint8_t*>(mmap(nullptr, 0x0AE16000, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    assert(image != MAP_FAILED);
    reset();
    lock_pages();
    const auto before = snapshot();
    post_unpack();
    assert(umbra_grown && raise_local_client_count && extension_stages == 1 && status_publications == 1 && !schedules);
    assert(protections == initial_protections);
    for (auto s : umbra_disps) {
        uint32_t value; std::memcpy(&value, image + s.rva + s.off, 4); assert(value == s.new_value);
    }
    for (auto u : umbra_bounds) assert(image[u.rva + 3] == u.new_value);
    // Check every other code byte, so a large accidentally copied span fails.
    auto expected = before;
    for (auto s : umbra_disps) std::memcpy(expected.data() + s.rva + s.off - 0x01C8C000, &s.new_value, 4);
    for (auto u : umbra_bounds) expected[u.rva + 3 - 0x01C8C000] = u.new_value;
    assert(snapshot() == expected);
    const auto successful_calls = protect_calls;
    *reinterpret_cast<uint64_t*>(image + umbra_object_rva) = 0x1234;
    assert(grow_umbra_client_arrays() && protect_calls == successful_calls); // idempotent

    reset(); *reinterpret_cast<uint64_t*>(image + umbra_object_rva) = 0x1234;
    lock_pages(); disabled(snapshot()); assert(protect_calls == 0);
    reset(); unreadable = image + umbra_object_rva;
    lock_pages(); disabled(snapshot()); assert(protect_calls == 0);
    for (auto s : umbra_disps) {
        reset(); image[s.rva + s.off] ^= 1; lock_pages(); disabled(snapshot()); assert(!protect_calls);
        reset(); unreadable = image + s.rva + s.off; lock_pages(); disabled(snapshot()); assert(!protect_calls);
    }
    for (auto u : umbra_bounds) {
        reset(); image[u.rva + 3] ^= 1; lock_pages(); disabled(snapshot()); assert(!protect_calls);
        reset(); unreadable = image + u.rva + 3; lock_pages(); disabled(snapshot()); assert(!protect_calls);
    }
    const int operands = std::size(umbra_disps) + std::size(umbra_bounds);
    for (int n = 1; n <= operands; ++n) {
        reset(); fail_at = n; lock_pages(); disabled(snapshot());
        assert(protect_calls == 2 * n - 1); // successful acquisitions all restored
    }
    reset(); image_ready = false; lock_pages();
    const auto unsettled = snapshot(); post_unpack();
    assert(schedules == 1 && !protect_calls && status_publications == 1 && !extension_stages);
    assert(snapshot() == unsettled);
    image_ready = true;
    *reinterpret_cast<uint64_t*>(image + umbra_object_rva) = 1;
    assert(scheduler::pending() == scheduler::cond_end); // terminal failure after retry
    assert(!protect_calls && status_publications == 2 && !raise_local_client_count && !extension_stages);

    // Synthetic stock layout: writing lc2's tome corrupts lc0's persistent
    // selector; growth keeps all four selectors independent and within allocation.
    std::vector<uint8_t> object(0x470300);
    const uint32_t marker = 0x11223344;
    std::memcpy(object.data() + 0x12DC48 + 2 * 4, &marker, 4);
    uint32_t aliased; std::memcpy(&aliased, object.data() + 0x12DC50, 4);
    assert(aliased == marker);
    std::memset(object.data(), 0, object.size());
    for (int lc = 0; lc != 4; ++lc) {
        const uint32_t selector = lc + 1;
        std::memcpy(object.data() + umbra_trig_new + lc * 4, &selector, 4);
    }
    for (int lc = 0; lc != 4; ++lc) {
        uint32_t selector, persistent;
        std::memcpy(&selector, object.data() + umbra_trig_new + lc * 4, 4);
        std::memcpy(&persistent, object.data() + umbra_ptrig_new + lc * 4, 4);
        assert(selector == uint32_t(lc + 1) && persistent == 0);
        assert(umbra_params_new + (lc + 1) * 0x14 <= umbra_trig_new);
    }
    std::printf("PASS: normal/idempotent growth, %d operand mismatches, %d unreadable operands, "
                "%d permission failures, object failures, startup/retry gate, selector separation\n",
                operands, operands, operands);
}
'''
    with tempfile.TemporaryDirectory(prefix="bo3-umbra-test-") as directory:
        source = Path(directory) / "test.cpp"
        executable = Path(directory) / "test"
        source.write_text(harness)
        subprocess.run([os.environ.get("CXX", "c++"), "-std=c++20", "-Wall", "-Wextra",
                        "-I" + str(ROOT / "src/standalone/compat"), str(source), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
    if args.image:
        inspect_image(args.image, addresses)


if __name__ == "__main__":
    main()
