// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Where the jar's natives come from. bindings/kotlin loads its shim with
// System.loadLibrary("sipral_jni"), which only ever searches
// java.library.path; this build rewrites each such call to [SipralNatives.load]
// (bindings/jvm/pom.xml), which takes the pair for the running JVM out of the
// jar, writes it to a private directory, loads it by absolute path and
// removes the files again. A library already mapped stays loaded once its
// file is gone, so nothing is left behind in the temporary directory.

package org.sipral.jvm

import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.Locale

/** A platform the jar carries natives for. */
enum class SipralPlatform(
    /** The directory under [SipralNatives.RESOURCE_ROOT] its pair sits in. */
    val id: String,
    /** ELF `e_machine`: what the pair's own headers have to say. */
    val elfMachine: Int,
) {
    LINUX_X64("linux-x64", 62),
    LINUX_ARM64("linux-arm64", 183),
    ;

    /** The resource directory this platform's pair is read from. */
    val resourceDirectory: String
        get() = "${SipralNatives.RESOURCE_ROOT}/$id"
}

/**
 * Loads `libsipral_ffi.so` and `libsipral_jni.so` for the running JVM, once.
 *
 * Every class of the binding that has native methods calls [load] as it is
 * initialised, so an application never has to; calling it first is how a
 * server finds out at start-up rather than at its first call that a native
 * does not load here. The system property [DIRECTORY_PROPERTY] names a
 * directory to load the pair from instead of the jar, for a library built
 * locally.
 */
object SipralNatives {
    /** Where the natives sit inside the jar. */
    const val RESOURCE_ROOT = "org/sipral/jvm/native"

    /** A directory holding the pair, loaded in place of the jar's. */
    const val DIRECTORY_PROPERTY = "sipral.native.dir"

    /** The C ABI. */
    const val FFI_LIBRARY = "libsipral_ffi.so"

    /** The JNI shim, linked against [FFI_LIBRARY] and finding it beside
     * itself (`$ORIGIN`). */
    const val JNI_LIBRARY = "libsipral_jni.so"

    /** Load order: the shim needs the ABI already mapped. */
    private val LIBRARIES = listOf(FFI_LIBRARY, JNI_LIBRARY)

    @Volatile
    private var loadedPlatform: SipralPlatform? = null

    @Volatile
    private var failure: UnsatisfiedLinkError? = null

    /**
     * The platform `os.name` and `os.arch` name, or null where the jar carries
     * nothing that would run. `os.arch` is spelled `amd64` by most JVMs and
     * `x86_64` by some; `aarch64` by all current ones, `arm64` by a few.
     */
    @JvmStatic
    fun platformOf(osName: String, osArch: String): SipralPlatform? {
        if (!osName.lowercase(Locale.ROOT).startsWith("linux")) {
            return null
        }
        return when (osArch.lowercase(Locale.ROOT)) {
            "amd64", "x86_64", "x86-64", "x64" -> SipralPlatform.LINUX_X64
            "aarch64", "arm64" -> SipralPlatform.LINUX_ARM64
            else -> null
        }
    }

    /** [platformOf] for the running JVM. */
    @JvmStatic
    fun currentPlatform(): SipralPlatform? =
        platformOf(System.getProperty("os.name") ?: "", System.getProperty("os.arch") ?: "")

    /** The platform whose pair [load] loaded, or null before it has. */
    @JvmStatic
    fun loaded(): SipralPlatform? = loadedPlatform

    /**
     * Load the pair, once per class loader; every later call returns at
     * once, and one that failed throws the same [UnsatisfiedLinkError] again
     * rather than trying a second time.
     */
    @JvmStatic
    fun load() {
        if (loadedPlatform != null) {
            return
        }
        synchronized(this) {
            if (loadedPlatform != null) {
                return
            }
            failure?.let { throw it }
            try {
                loadedPlatform = loadNow()
            } catch (refused: UnsatisfiedLinkError) {
                failure = refused
                throw refused
            }
        }
    }

    private fun loadNow(): SipralPlatform {
        val platform = currentPlatform()
            ?: throw UnsatisfiedLinkError(
                "sipral: no native library for ${System.getProperty("os.name")} on " +
                    "${System.getProperty("os.arch")}; this jar carries " +
                    SipralPlatform.entries.joinToString(", ") { it.id },
            )
        val directory = System.getProperty(DIRECTORY_PROPERTY)
        if (!directory.isNullOrEmpty()) {
            for (library in LIBRARIES) {
                val path = Paths.get(directory, library).toAbsolutePath()
                try {
                    checkElf(Files.newInputStream(path), platform, path.toString())
                } catch (cannot: IOException) {
                    throw linkError("sipral: could not read $path, named by $DIRECTORY_PROPERTY", cannot)
                }
                System.load(path.toString())
            }
            return platform
        }
        val staging = try {
            Files.createTempDirectory(
                "sipral-natives-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
            )
        } catch (cannot: IOException) {
            throw linkError("sipral: could not create a directory to load the natives from", cannot)
        }
        try {
            for (library in LIBRARIES) {
                val resource = "${platform.resourceDirectory}/$library"
                val stream = SipralNatives::class.java.classLoader.getResourceAsStream(resource)
                    ?: throw UnsatisfiedLinkError(
                        "sipral: $resource is not in the jar, so ${platform.id} cannot load",
                    )
                val target = staging.resolve(library)
                stream.use { Files.copy(it, target, StandardCopyOption.REPLACE_EXISTING) }
                checkElf(Files.newInputStream(target), platform, resource)
            }
            for (library in LIBRARIES) {
                System.load(staging.resolve(library).toString())
            }
        } catch (cannot: IOException) {
            throw linkError("sipral: could not write the natives out of the jar", cannot)
        } finally {
            for (library in LIBRARIES) {
                runCatching { Files.deleteIfExists(staging.resolve(library)) }
            }
            runCatching { Files.deleteIfExists(staging) }
        }
        return platform
    }

    /**
     * The ELF machine [stream] opens with, or -1 for a file that is not a
     * 64-bit little-endian ELF shared object. Closes [stream].
     */
    @JvmStatic
    fun elfMachineOf(stream: InputStream): Int {
        val header = stream.use { it.readNBytes(20) }
        if (header.size < 20) return -1
        val magic = header[0] == 0x7f.toByte() && header[1] == 'E'.code.toByte() &&
            header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte()
        // EI_CLASS 2 is 64-bit, EI_DATA 1 little-endian, e_type 3 ET_DYN.
        val shape = header[4].toInt() == 2 && header[5].toInt() == 1 &&
            (header[16].toInt() and 0xff) == 3 && header[17].toInt() == 0
        if (!magic || !shape) return -1
        return (header[18].toInt() and 0xff) or ((header[19].toInt() and 0xff) shl 8)
    }

    private fun checkElf(stream: InputStream, platform: SipralPlatform, name: String) {
        val machine = elfMachineOf(stream)
        if (machine != platform.elfMachine) {
            throw UnsatisfiedLinkError(
                "sipral: $name is not a shared object for ${platform.id} " +
                    "(ELF machine $machine, expected ${platform.elfMachine})",
            )
        }
    }

    private fun linkError(message: String, cause: Throwable): UnsatisfiedLinkError =
        UnsatisfiedLinkError("$message: ${cause.message}").apply { initCause(cause) }
}
