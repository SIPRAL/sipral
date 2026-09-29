# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

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

from sipral._sipral_cffi import ffi, lib

_REPO_ROOT = Path(__file__).resolve().parents[3]
_HEADER = _REPO_ROOT / "bindings" / "c" / "include" / "sipral.h"
_ABI_SIZES = _REPO_ROOT / "bindings" / "c" / "abi-sizes.txt"

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


class StructSizesMatchAbiSizes(unittest.TestCase):
    """`ffi.sizeof` for every record `bindings/c/abi-sizes.txt` names.

    cffi's ABI mode lays a struct out for itself from the `cdef` text --
    nothing here links against a compiled definition -- so this is the one
    check that would catch the `cdef` silently drifting from what a real C
    compiler puts in `bindings/c/abi-sizes.txt`'s own second column, which
    `scripts/check.sh` already keeps current against this build
    (`docs/08-ffi.md`, "Versioning").
    """

    @classmethod
    def setUpClass(cls) -> None:
        if not _ABI_SIZES.is_file():
            raise unittest.SkipTest(f"{_ABI_SIZES} not found; run from a checkout")
        cls.rows: list[tuple[str, int]] = []
        for line in _ABI_SIZES.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _first, current = line.split()
            if current == "-":
                continue  # filled in by the library alone; no caller declares one
            cls.rows.append((name, int(current)))

    def test_every_versioned_struct_is_the_size_this_build_says(self) -> None:
        self.assertGreater(len(self.rows), 5)
        for name, current in self.rows:
            with self.subTest(struct=name):
                self.assertEqual(ffi.sizeof(name), current)


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
