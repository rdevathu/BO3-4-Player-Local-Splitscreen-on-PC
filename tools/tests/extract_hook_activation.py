r"""Extract actual component code for hook_activation.cpp (no game required).

Usage: python tools/tests/extract_hook_activation.py BUILD_DIRECTORY
Then build on Windows with the project's MSVC compiler and MinHook headers:
  cl /std:c++20 /EHsc /I%MINHOOK%\include /IBUILD_DIRECTORY
     /Isrc\standalone\compat tools\tests\hook_activation.cpp
     src\standalone\runtime.cpp /Fe:BUILD_DIRECTORY\hook_activation.exe
Run the executable normally and again with --init-failure.

MinHook entry points are supplied by the fixture, not linked from MinHook.
The extracted helper, file lists and read filter are unchanged production code.
"""
from pathlib import Path
import sys


def braced_definition(source, marker):
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if source[end:end + 1] == ";":
        end += 1
    return source[start:end]


root = Path(__file__).resolve().parents[2]
core = (root / "src/component/splitscreen/01_core.inl").read_text()
seats = (root / "src/component/splitscreen/03_signin_seats.inl").read_text()
parts = [braced_definition(core, "template <size_t N, typename F>\n\t\tbool hook_if_stock")]
for name in ("guest_allowed_file_types", "guest_seated_file_types"):
    parts.append(braced_definition(seats, "constexpr uint32_t " + name))
for name in ("settings_result_neutered", "shoutcaster_result_neutered"):
    marker = "bool " + name
    start = seats.index(marker)
    parts.append(seats[start:seats.index(";", start) + 1])
parts.append(braced_definition(seats, "bool storage_read_stub("))
output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
(output / "hook_activation_component.inc").write_text("\n\n".join(parts) + "\n")
