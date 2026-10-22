// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The account screen's telecom choice: either adapter when one is named,
// and the library's choice for the release otherwise, including a value an
// older or newer build stored that this one does not know.

package org.sipral.sample

import org.sipral.android.telecom.SipralTelecomAdapter
import org.testng.Assert.assertEquals
import org.testng.annotations.Test

class TelecomChoiceTest {
    @Test
    fun aNamedAdapterIsUsedOnEveryRelease() {
        for (sdk in listOf(26, 33, 34, 37)) {
            assertEquals(telecomAdapterOf("connection-service", sdk), SipralTelecomAdapter.CONNECTION_SERVICE)
            assertEquals(telecomAdapterOf("core-telecom", sdk), SipralTelecomAdapter.CORE_TELECOM)
        }
    }

    @Test
    fun automaticIsCoreTelecomFromAndroid14() {
        assertEquals(telecomAdapterOf("auto", 33), SipralTelecomAdapter.CONNECTION_SERVICE)
        assertEquals(telecomAdapterOf("auto", 34), SipralTelecomAdapter.CORE_TELECOM)
        assertEquals(telecomAdapterOf("something else", 36), SipralTelecomAdapter.CORE_TELECOM)
        assertEquals(AccountSettings().telecom, "auto")
    }
}
