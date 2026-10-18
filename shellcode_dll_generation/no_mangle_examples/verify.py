"""Call the compiled example through its native exports using Python's standard library."""

import ctypes
from pathlib import Path
import sys


def main():
    names = {
        "win32": "study_exports_demo.dll",
        "linux": "libstudy_exports_demo.so",
        "darwin": "libstudy_exports_demo.dylib",
    }
    if sys.platform not in names:
        raise SystemExit(f"Unsupported platform for this example: {sys.platform}")

    library_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parent / "target" / "debug" / names[sys.platform]
    ).resolve()
    if not library_path.is_file():
        raise SystemExit(f"Build the library first; file not found: {library_path}")

    # The exports use extern "C", so use CDLL rather than a Windows stdcall loader.
    library = ctypes.CDLL(str(library_path))
    add = library.crto_study_add_v1
    add.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    add.restype = ctypes.c_uint32

    version = library.crto_study_version_v1
    version.argtypes = []
    version.restype = ctypes.c_uint32

    metadata = ctypes.c_uint32.in_dll(library, "CRTO_STUDY_ABI_VERSION")

    # Explicit checks also run if Python is launched with -O.
    for label, actual, expected in (
        ("add(2, 3)", add(2, 3), 5),
        ("add(0xffffffff, 1)", add(0xFFFFFFFF, 1), 0),
        ("version()", version(), 1),
        ("CRTO_STUDY_ABI_VERSION", metadata.value, 1),
    ):
        if actual != expected:
            raise SystemExit(f"{label}: expected {expected}, got {actual}")
        print(f"{label} = {actual}")

    print("All native export checks passed.")


if __name__ == "__main__":
    main()
