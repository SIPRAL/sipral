// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The loader's choice: which pair each os.name and os.arch get, that each
// pair the build staged is an ELF shared object for the machine its
// directory names, and that the running JVM loads its own pair once.

package org.sipral.jvm

import java.io.ByteArrayInputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

class SipralNativesTest {
    @Test
    fun linuxOnX64SpellingsChooseLinuxX64() {
        for (arch in listOf("amd64", "x86_64", "X86_64", "x86-64", "x64")) {
            assertSame(SipralPlatform.LINUX_X64, SipralNatives.platformOf("Linux", arch), arch)
        }
    }

    @Test
    fun linuxOnArm64SpellingsChooseLinuxArm64() {
        for (arch in listOf("aarch64", "arm64", "AArch64")) {
            assertSame(SipralPlatform.LINUX_ARM64, SipralNatives.platformOf("Linux", arch), arch)
        }
    }

    @Test
    fun anythingElseChoosesNothing() {
        assertNull(SipralNatives.platformOf("Linux", "arm"))
        assertNull(SipralNatives.platformOf("Linux", "x86"))
        assertNull(SipralNatives.platformOf("Linux", "riscv64"))
        assertNull(SipralNatives.platformOf("Linux", "ppc64le"))
        assertNull(SipralNatives.platformOf("Mac OS X", "aarch64"))
        assertNull(SipralNatives.platformOf("Windows 11", "amd64"))
        assertNull(SipralNatives.platformOf("FreeBSD", "amd64"))
    }

    @Test
    fun eachPlatformReadsItsOwnDirectory() {
        assertEquals("org/sipral/jvm/native/linux-x64", SipralPlatform.LINUX_X64.resourceDirectory)
        assertEquals("org/sipral/jvm/native/linux-arm64", SipralPlatform.LINUX_ARM64.resourceDirectory)
    }

    @Test
    fun theElfMachineIsReadFromTheHeader() {
        fun header(machine: Int, bits: Int = 2, type: Int = 3): ByteArray = ByteArray(64).also {
            it[0] = 0x7f
            it[1] = 'E'.code.toByte()
            it[2] = 'L'.code.toByte()
            it[3] = 'F'.code.toByte()
            it[4] = bits.toByte()
            it[5] = 1
            it[16] = type.toByte()
            it[18] = (machine and 0xff).toByte()
            it[19] = (machine shr 8).toByte()
        }
        assertEquals(62, SipralNatives.elfMachineOf(ByteArrayInputStream(header(62))))
        assertEquals(183, SipralNatives.elfMachineOf(ByteArrayInputStream(header(183))))
        assertEquals(-1, SipralNatives.elfMachineOf(ByteArrayInputStream(header(40, bits = 1))), "32-bit")
        assertEquals(-1, SipralNatives.elfMachineOf(ByteArrayInputStream(header(62, type = 2))), "an executable")
        assertEquals(-1, SipralNatives.elfMachineOf(ByteArrayInputStream("not an ELF file".toByteArray())))
        assertEquals(-1, SipralNatives.elfMachineOf(ByteArrayInputStream(ByteArray(3))))
    }

    /** Every pair the build staged -- both of them in a full build -- is for
     * the machine its directory names. */
    @Test
    fun eachStagedPairIsForItsOwnMachine() {
        val loader = SipralNatives::class.java.classLoader
        var staged = 0
        for (platform in SipralPlatform.entries) {
            for (library in listOf(SipralNatives.FFI_LIBRARY, SipralNatives.JNI_LIBRARY)) {
                val stream = loader.getResourceAsStream("${platform.resourceDirectory}/$library") ?: continue
                assertEquals(platform.elfMachine, SipralNatives.elfMachineOf(stream), "${platform.id}/$library")
                staged++
            }
        }
        val expected = System.getProperty("sipral.expected.platforms")?.split(',')?.filter { it.isNotBlank() }
        if (expected != null) {
            assertEquals(expected.size * 2, staged, "the natives staged for $expected")
        }
    }

    /** The running JVM's own pair loads, and a second load is a no-op. */
    @Test
    fun theRunningJvmLoadsItsOwnPair() {
        val platform = SipralNatives.currentPlatform()
        assertNotNull(platform, "the JVM this test runs on is one the jar carries natives for")
        SipralNatives.load()
        assertSame(platform, SipralNatives.loaded())
        SipralNatives.load()
        assertSame(platform, SipralNatives.loaded())
        assertEquals(0L, org.sipral.Sipral.abiVersion().major)
    }
}
