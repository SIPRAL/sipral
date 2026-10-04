# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Two ways `_sipral_cffi.py` could quietly stop matching the ABI it was
printed for, that a call placed between two stacks never exercises.

Both files -- `bindings/c/include/sipral.h` and
`bindings/python/sipral/_sipral_cffi.py` -- are printed from the same
`sipral_ffi::abi::SURFACE` by `tools/abi-gen` (`docs/08-ffi.md`, "One
declaration, and four files printed from it"), so in an honest build they
cannot disagree; what these tests catch is this package answering from a
stale `_sipral_cffi.py` that was not regenerated after the header moved.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from cffi import FFI

from sipral._sipral_cffi import RECORD_LAYOUTS, ffi, lib

_REPO_ROOT = Path(__file__).resolve().parents[3]
_HEADER = _REPO_ROOT / "bindings" / "c" / "include" / "sipral.h"
_ABI_SIZES = _REPO_ROOT / "bindings" / "c" / "abi-sizes.txt"

# The structs that carry their own size, as `bindings/c/abi-sizes.txt` lists
# them: the ones `sipral_abi_struct_size` answers for.
_VERSIONED = (
    [line.split()[0] for line in _ABI_SIZES.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    if _ABI_SIZES.is_file()
    else []
)

# `#define NAME ((TYPE)VALUE)`, as `tools/abi-gen/src/c.rs`'s `values`
# prints every published constant.
_DEFINE = re.compile(r"^#define\s+(SIPRAL_\w+)\s+\(\([\w\s]+\)(-?\d+)\)\s*$", re.MULTILINE)

# `SIPRAL_NAME = 123,` inside one of the header's anonymous `enum { ... }`
# blocks, as `tools/abi-gen/src/c.rs`'s `enumerations` prints one.
_ENUMERATOR = re.compile(r"^\s*(SIPRAL_\w+)\s*=\s*(-?\d+),?\s*$", re.MULTILINE)


class ConstantsMatchTheHeader(unittest.TestCase):
    """Every `SIPRAL_*` numeral the header declares, read back off `lib`."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _HEADER.is_file():
            raise unittest.SkipTest(f"header not found at {_HEADER}; run from a checkout")
        cls.text = _HEADER.read_text(encoding="utf-8")

    def test_every_define_is_readable_and_equal(self) -> None:
        found = _DEFINE.findall(self.text)
        self.assertGreater(len(found), 20, "the header's own #define lines should number in the dozens")
        for name, value in found:
            with self.subTest(name=name):
                self.assertTrue(hasattr(lib, name), f"{name} is in the header but not in _sipral_cffi.py")
                self.assertEqual(int(getattr(lib, name)), int(value))

    def test_every_enumerator_is_readable_and_equal(self) -> None:
        found = _ENUMERATOR.findall(self.text)
        self.assertGreater(len(found), 50, "the header declares many more enumerators than this")
        for name, value in found:
            with self.subTest(name=name):
                self.assertTrue(hasattr(lib, name), f"{name} is in the header but not in _sipral_cffi.py")
                self.assertEqual(int(getattr(lib, name)), int(value))


def _layout() -> int:
    """Which of the three layouts `RECORD_LAYOUTS` lists this process is on:
    64-bit pointers, or 32-bit ones with a 64-bit integer aligned to four
    (i386) or to eight (ARM, Windows x86) inside a struct."""
    if ffi.sizeof("void *") == 8:
        return 0
    probe = FFI()
    probe.cdef("struct probe { char before; uint64_t value; };")
    return 1 if probe.offsetof("struct probe", "value") == 4 else 2


class StructSizesMatchTheLayouts(unittest.TestCase):
    """`ffi.sizeof` for every record, held to the length tools/abi-gen
    worked out for the layout this process is on, and to what the library
    itself says.

    cffi's ABI mode lays a struct out for itself from the `cdef` text --
    nothing here links against a compiled definition -- so this is the one
    check that would catch the `cdef` silently drifting from what a real C
    compiler makes of the header, which `bindings/c/abi-layout.c` holds to
    the same table on six targets (`docs/08-ffi.md`, "Versioning").
    """

    def test_every_record_is_as_long_as_the_layout_says(self) -> None:
        self.assertGreater(len(RECORD_LAYOUTS), 50)
        layout = _layout()
        size = ffi.new("size_t *")
        for name, lengths in RECORD_LAYOUTS.items():
            with self.subTest(record=name):
                self.assertEqual(ffi.sizeof(name), lengths[layout])
                encoded = name.encode()
                status = lib.sipral_abi_struct_size(encoded, len(encoded), size)
                self.assertEqual(status, lib.SIPRAL_STATUS_OK)
                self.assertEqual(size[0], lengths[layout])

    def test_every_versioned_struct_is_in_the_table(self) -> None:
        count = ffi.new("size_t *")
        self.assertEqual(lib.sipral_abi_versioned_count(count), lib.SIPRAL_STATUS_OK)
        self.assertEqual(len(_VERSIONED), count[0])
        for name in _VERSIONED:
            self.assertIn(name, RECORD_LAYOUTS)


class TheAbiCheckKeepsTheOneXRule(unittest.TestCase):
    """The check `_sipral_cffi.py` makes at import, asked of the library it
    loaded about other versions than its own: within one major a binding
    built against an earlier or equal minor is served, and one built against
    a later minor, another major or any 0.x is refused, naming the caller's
    version."""

    def _library(self) -> tuple[int, int]:
        version = ffi.new("sipral_abi_version_t *")
        version.size = ffi.sizeof("sipral_abi_version_t")
        self.assertEqual(lib.sipral_abi_version(version), lib.SIPRAL_STATUS_OK)
        return version.major, version.minor

    def _refused(self, major: int, minor: int) -> None:
        from sipral.errors import SipralError, check

        with self.assertRaises(SipralError) as raised:
            check(lib.sipral_abi_check(major, minor), "sipral_abi_check")
        self.assertEqual(raised.exception.status, lib.SIPRAL_STATUS_UNSUPPORTED_VERSION)
        self.assertIn(f"{major}.{minor}", str(raised.exception))

    def test_the_library_is_at_this_bindings_major_and_no_earlier_minor(self) -> None:
        major, minor = self._library()
        self.assertEqual(major, lib.SIPRAL_ABI_VERSION_MAJOR)
        self.assertGreaterEqual(minor, lib.SIPRAL_ABI_VERSION_MINOR)

    def test_the_minor_this_binding_was_printed_against_is_served(self) -> None:
        status = lib.sipral_abi_check(lib.SIPRAL_ABI_VERSION_MAJOR, lib.SIPRAL_ABI_VERSION_MINOR)
        self.assertEqual(status, lib.SIPRAL_STATUS_OK)

    def test_a_binding_built_against_an_earlier_minor_is_served(self) -> None:
        """A library newer than its binding: every earlier minor of this
        major is a binding the library in hand is newer than."""
        major, library_minor = self._library()
        for minor in range(library_minor + 1):
            with self.subTest(minor=minor):
                self.assertEqual(lib.sipral_abi_check(major, minor), lib.SIPRAL_STATUS_OK)

    def test_a_binding_built_against_a_later_minor_is_refused(self) -> None:
        major, minor = self._library()
        self._refused(major, minor + 1)

    def test_another_major_is_refused(self) -> None:
        self._refused(lib.SIPRAL_ABI_VERSION_MAJOR + 1, 0)
        self._refused(0, 36)


class SrtpSuitesHaveNames(unittest.TestCase):
    """`SrtpSuite` names every transform the stack runs, RFC 6188's and
    RFC 7714's included, so a MEDIA_SECURED event's `suite` reads as one."""

    def test_every_suite_the_stack_runs_is_a_member(self) -> None:
        from sipral.enums import SrtpSuite

        self.assertEqual(
            {member.name: int(member) for member in SrtpSuite},
            {
                "UNKNOWN": 0,
                "AES_CM80": 1,
                "AES_CM32": 2,
                "AES_F8": 3,
                "AES256_CM80": 4,
                "AES256_CM32": 5,
                "AEAD_AES128_GCM": 6,
                "AEAD_AES256_GCM": 7,
            },
        )


class Abi29SpacesHaveNames(unittest.TestCase):
    """Every numbered space ABI 0.29 added is read off `lib` whole, and none
    swallows a neighbour that shares its start."""

    def test_each_space_holds_exactly_its_own_values(self) -> None:
        from sipral import enums

        expected = {
            enums.AudioMode: {"APPLICATION": 0, "DEVICE": 1},
            enums.AudioActivation: {"AUTOMATIC": 0, "MANUAL": 1},
            enums.AudioRole: {"MICROPHONE": 1, "SPEAKER": 2, "RINGER": 3},
            enums.AudioDirection: {"INPUT": 1, "OUTPUT": 2},
            enums.AudioOrigin: {"SYSTEM": 1, "ENGINE": 2},
            enums.SessionTimer: {"DEFAULT": 0, "OFF": 1, "INTERVAL": 2},
            enums.RingSource: {"UNKNOWN": 0, "INTERNAL": 1, "EXTERNAL": 2},
        }
        for space, members in expected.items():
            with self.subTest(space=space.__name__):
                self.assertEqual({m.name: int(m) for m in space}, members)
        self.assertNotIn("OUTCOME_RUNNING", enums.Recovery.__members__)
        self.assertEqual(int(enums.Recovery.REBUILD), lib.SIPRAL_RECOVERY_REBUILD)
        self.assertEqual(int(enums.Privacy.ID), lib.SIPRAL_PRIVACY_ID)
        self.assertEqual(int(enums.Feature.AUDIO_DEVICE), lib.SIPRAL_FEATURE_AUDIO_DEVICE)
        self.assertEqual(int(enums.Feature.CALL_READDRESS), lib.SIPRAL_FEATURE_CALL_READDRESS)
        self.assertEqual(len(enums.AudioChange), 6)
        self.assertEqual(len(enums.IdentityText), 16)

    def test_this_build_says_what_it_has(self) -> None:
        from sipral import features
        from sipral.enums import Feature

        have = features()
        self.assertIn(Feature.CALLER_IDENTITY, have)
        self.assertIn(Feature.CALL_READDRESS, have)
        self.assertIn(Feature.TURN_STREAM, have)


if __name__ == "__main__":
    unittest.main()
