/*
 * Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matrix.androidsdk.crypto

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import junit.framework.Assert
import junit.framework.Assert.*
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import org.matrix.androidsdk.common.*
import org.matrix.androidsdk.crypto.data.ImportRoomKeysResult
import org.matrix.androidsdk.crypto.data.MXDeviceInfo
import org.matrix.androidsdk.crypto.keysbackup.KeyBackupVersionTrust
import org.matrix.androidsdk.crypto.keysbackup.KeysBackup
import org.matrix.androidsdk.crypto.keysbackup.KeysBackupStateManager
import org.matrix.androidsdk.crypto.keysbackup.MegolmBackupCreationInfo
import org.matrix.androidsdk.rest.callback.SuccessCallback
import org.matrix.androidsdk.rest.callback.SuccessErrorCallback
import org.matrix.androidsdk.rest.model.keys.KeysVersion
import org.matrix.androidsdk.rest.model.keys.KeysVersionResult
import java.lang.Exception
import java.util.concurrent.CountDownLatch

@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class KeysBackupTest {

    private val mTestHelper = CommonTestHelper()
    private val mCryptoTestHelper = CryptoTestHelper(mTestHelper)

    private val defaultSessionParams = SessionTestParams.newBuilder()
            .withCryptoEnabled(true)
            .build()

    /**
     * - From doE2ETestWithAliceAndBobInARoomWithEncryptedMessages, we should have no backed up keys
     * - Check backup keys after having marked one as backed up
     * - Reset keys backup markers
     */
    @Test
    fun roomKeysTest_testBackupStore_ok() {
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val store = cryptoTestData.firstSession.crypto!!.cryptoStore

        // From doE2ETestWithAliceAndBobInARoomWithEncryptedMessages, we should have no backed up keys
        val sessions = store.inboundGroupSessionsToBackup(100)
        val sessionsCount = sessions.size

        Assert.assertFalse(sessions.isEmpty())
        Assert.assertEquals(sessionsCount, store.inboundGroupSessionsCount(false))
        Assert.assertEquals(0, store.inboundGroupSessionsCount(true))

        // - Check backup keys after having marked one as backed up
        val session = sessions[0]

        store.markBackupDoneForInboundGroupSessionWithId(session.mSession.sessionIdentifier(), session.mSenderKey)

        Assert.assertEquals(sessionsCount, store.inboundGroupSessionsCount(false))
        Assert.assertEquals(1, store.inboundGroupSessionsCount(true))

        val sessions2 = store.inboundGroupSessionsToBackup(100)
        Assert.assertEquals(sessionsCount - 1, sessions2.size)

        // - Reset keys backup markers
        store.resetBackupMarkers()

        val sessions3 = store.inboundGroupSessionsToBackup(100)
        Assert.assertEquals(sessionsCount, sessions3.size)
        Assert.assertEquals(sessionsCount, store.inboundGroupSessionsCount(false))
        Assert.assertEquals(0, store.inboundGroupSessionsCount(true))
    }

    /**
     * Check that prepareKeysBackupVersion returns valid data
     */
    @Test
    fun prepareKeysBackupVersionTest() {
        val bobSession = mTestHelper.createAccount(TestConstants.USER_BOB, defaultSessionParams)

        bobSession.enableCrypto()

        assertNotNull(bobSession.crypto)
        assertNotNull(bobSession.crypto!!.keysBackup)

        val keysBackup = bobSession.crypto!!.keysBackup

        assertFalse(keysBackup.isEnabled)

        val latch = CountDownLatch(1)

        keysBackup.prepareKeysBackupVersion(object : SuccessErrorCallback<MegolmBackupCreationInfo> {
            override fun onSuccess(info: MegolmBackupCreationInfo?) {
                assertNotNull(info)

                assertEquals(MXCRYPTO_ALGORITHM_MEGOLM_BACKUP, info!!.algorithm)
                assertNotNull(info.authData)
                assertNotNull(info.authData!!.publicKey)
                assertNotNull(info.authData!!.signatures)
                assertNotNull(info.recoveryKey)

                latch.countDown()
            }

            override fun onUnexpectedError(e: Exception?) {
                Assert.fail(e?.localizedMessage)

                latch.countDown()
            }
        })
        latch.await()

        bobSession.clear(InstrumentationRegistry.getContext())
    }

    /**
     * Test creating a keys backup version and check that createKeyBackupVersion() returns valid data
     */
    @Test
    fun createKeyBackupVersionTest() {
        val bobSession = mTestHelper.createAccount(TestConstants.USER_BOB, defaultSessionParams)
        bobSession.enableCrypto()

        val keysBackup = bobSession.crypto!!.keysBackup

        assertFalse(keysBackup.isEnabled)

        var megolmBackupCreationInfo: MegolmBackupCreationInfo? = null
        val latch = CountDownLatch(1)
        keysBackup.prepareKeysBackupVersion(object : SuccessErrorCallback<MegolmBackupCreationInfo> {

            override fun onSuccess(info: MegolmBackupCreationInfo) {
                megolmBackupCreationInfo = info

                latch.countDown()
            }

            override fun onUnexpectedError(e: Exception) {
                Assert.fail(e.localizedMessage)

                latch.countDown()
            }
        })
        latch.await()

        assertNotNull(megolmBackupCreationInfo)

        assertFalse(keysBackup.isEnabled)

        val latch2 = CountDownLatch(1)

        // Create the version
        keysBackup.createKeyBackupVersion(megolmBackupCreationInfo!!, object : TestApiCallback<KeysVersion>(latch2) {
            override fun onSuccess(info: KeysVersion) {
                assertNotNull(info)
                assertNotNull(info.version)

                // Backup must be enable now
                assertTrue(keysBackup.isEnabled)

                super.onSuccess(info)
            }
        })
        mTestHelper.await(latch2)

        bobSession.clear(InstrumentationRegistry.getContext())
    }

    /**
     * - Check that createKeyBackupVersion() launches the backup
     * - Check the backup completes
     */
    @Test
    fun backupAfterCreateKeyBackupVersionTest() {
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val cryptoStore = cryptoTestData.firstSession.crypto!!.cryptoStore
        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        prepareAndCreateKeyBackupData(keysBackup)

        // Check that createKeyBackupVersion() launches the backup
        Assert.assertTrue(keysBackup.state == KeysBackupStateManager.KeysBackupState.Enabling
                || keysBackup.state == KeysBackupStateManager.KeysBackupState.WillBackUp)

        val keys = cryptoStore.inboundGroupSessionsCount(false)

        val latch3 = CountDownLatch(1)
        keysBackup.addListener(object : KeysBackupStateManager.KeysBackupStateListener {
            override fun onStateChange(newState: KeysBackupStateManager.KeysBackupState) {
                // Check the backup completes
                if (keysBackup.state == KeysBackupStateManager.KeysBackupState.ReadyToBackUp) {
                    // Remove itself from the list of listeners
                    keysBackup.removeListener(this)

                    val backedUpKeys = cryptoStore.inboundGroupSessionsCount(true)

                    Assert.assertEquals("All keys must have been marked as backed up", keys, backedUpKeys)
                    latch3.countDown()
                }
            }
        })
        mTestHelper.await(latch3)

        cryptoTestData.clear(context)
    }


    /**
     * Check that backupAllGroupSessions() returns valid data
     */
    @Test
    fun backupAllGroupSessionsTest() {
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val cryptoStore = cryptoTestData.firstSession.crypto!!.cryptoStore
        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        prepareAndCreateKeyBackupData(keysBackup)

        // Check that backupAllGroupSessions returns valid data
        val keys = cryptoStore.inboundGroupSessionsCount(false)

        val latch = CountDownLatch(1)

        var lastBackedUpKeysProgress = 0

        keysBackup.backupAllGroupSessions(object : KeysBackup.BackupProgress {
            override fun onProgress(backedUp: Int, total: Int) {
                Assert.assertEquals(keys, total)
                lastBackedUpKeysProgress = backedUp
            }

        }, TestApiCallback(latch))

        mTestHelper.await(latch)

        val backedUpKeys = cryptoStore.inboundGroupSessionsCount(true)

        Assert.assertEquals("All keys must have been marked as backed up", keys, backedUpKeys)
        Assert.assertEquals(lastBackedUpKeysProgress, keys)

        cryptoTestData.clear(context)
    }

    /**
     * Check encryption and decryption of megolm keys in the backup.
     * - Pick a megolm key
     * - Check [MXKeyBackup encryptGroupSession] returns stg
     * - Check [MXKeyBackup pkDecryptionFromRecoveryKey] is able to create a OLMPkDecryption
     * - Check [MXKeyBackup decryptKeyBackupData] returns stg
     * - Compare the decrypted megolm key with the original one
     */
    @Test
    fun testEncryptAndDecryptKeyBackupData() {
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val cryptoStore = cryptoTestData.firstSession.crypto!!.cryptoStore
        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        // - Pick a megolm key
        val session = cryptoStore.inboundGroupSessionsToBackup(1)[0]

        val keyBackupCreationInfo = prepareAndCreateKeyBackupData(keysBackup).first

        // - Check encryptGroupSession() returns stg
        val keyBackupData = keysBackup.encryptGroupSession(session)
        Assert.assertNotNull(keyBackupData)
        Assert.assertNotNull(keyBackupData.sessionData)

        // - Check pkDecryptionFromRecoveryKey() is able to create a OlmPkDecryption
        val decryption = keysBackup.pkDecryptionFromRecoveryKey(keyBackupCreationInfo.recoveryKey)
        Assert.assertNotNull(decryption)
        // - Check decryptKeyBackupData() returns stg
        val sessionData = keysBackup.decryptKeyBackupData(keyBackupData, session.mSession.sessionIdentifier(), cryptoTestData.roomId, decryption)
        Assert.assertNotNull(sessionData)
        // - Compare the decrypted megolm key with the original one
        Assert.assertEquals(session.exportKeys(), sessionData)

        cryptoTestData.clear(context)
    }

    /**
     * - Do an e2e backup to the homeserver
     * - Log Alice on a new device
     * - Restore the e2e backup from the homeserver
     * - Imported keys number must be correct
     * - The new device must have the same count of megolm keys
     * - Alice must have the same keys on both devices
     */
    @Test
    fun restoreKeyBackupTest() {
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val cryptoStore = cryptoTestData.firstSession.crypto!!.cryptoStore
        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        val aliceKeys1 = cryptoStore.inboundGroupSessionsToBackup(100)

        // - Do an e2e backup to the homeserver
        val info = prepareAndCreateKeyBackupData(keysBackup)
        val keyBackupCreationInfo = info.first
        val version = info.second

        val latch = CountDownLatch(1)
        keysBackup.backupAllGroupSessions(object : KeysBackup.BackupProgress {
            override fun onProgress(backedUp: Int, total: Int) {
                // Nothing to do
            }
        }, TestApiCallback(latch))
        mTestHelper.await(latch)

        // - Log Alice on a new device
        val aliceSession2 = mTestHelper.logIntoAccount(cryptoTestData.firstSession.myUserId, defaultSessionParams)

        // Test check: aliceSession2 has no keys at login
        Assert.assertEquals(0, aliceSession2.crypto!!.cryptoStore.inboundGroupSessionsCount(false))

        // - Restore the e2e backup from the homeserver
        val latch2 = CountDownLatch(1)
        aliceSession2.crypto!!.keysBackup.restoreKeyBackup(version,
                keyBackupCreationInfo.recoveryKey,
                null,
                null,
                object : TestApiCallback<ImportRoomKeysResult>(latch2) {
                    override fun onSuccess(info: ImportRoomKeysResult) {
                        // - Imported keys number must be correct
                        Assert.assertEquals(aliceKeys1.size, info.totalNumberOfKeys)
                        Assert.assertEquals(info.totalNumberOfKeys, info.successfullyNumberOfImportedKeys)
                        // - The new device must have the same count of megolm keys
                        Assert.assertEquals(aliceKeys1.size, aliceSession2.crypto!!.cryptoStore.inboundGroupSessionsCount(false))
                        // - Alice must have the same keys on both devices
                        for (aliceKey1 in aliceKeys1) {
                            val aliceKey2 = aliceSession2.crypto!!
                                    .cryptoStore.getInboundGroupSession(aliceKey1.mSession.sessionIdentifier(), aliceKey1.mSenderKey)
                            Assert.assertNotNull(aliceKey2)
                            Assert.assertEquals(aliceKey1.exportKeys(), aliceKey2.exportKeys())
                        }

                        super.onSuccess(info)
                    }
                }
        )
        mTestHelper.await(latch2)

        cryptoTestData.clear(context)
    }

    /**
     * - Create a backup version
     * - Check the returned MXKeyBackupVersion is trusted
     */
    @Test
    fun testIsKeyBackupTrusted() {
        // - Create a backup version
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        // - Do an e2e backup to the homeserver
        val info = prepareAndCreateKeyBackupData(keysBackup)

        // Get key backup version from the home server
        var keysVersionResult: KeysVersionResult? = null
        val lock = CountDownLatch(1)
        keysBackup.getCurrentVersion(object : TestApiCallback<KeysVersionResult?>(lock) {
            override fun onSuccess(info: KeysVersionResult?) {
                keysVersionResult = info
                super.onSuccess(info)
            }
        })
        mTestHelper.await(lock)

        Assert.assertNotNull(keysVersionResult)

        // - Check the returned KeyBackupVersion is trusted
        val latch = CountDownLatch(1)
        keysBackup.isKeyBackupTrusted(keysVersionResult!!, object : SuccessCallback<KeyBackupVersionTrust> {
            override fun onSuccess(info: KeyBackupVersionTrust?) {
                Assert.assertNotNull(info)
                Assert.assertTrue(info!!.usable)
                Assert.assertEquals(1, info.signatures.size)

                val signature = info.signatures[0]
                Assert.assertTrue(signature.valid)
                Assert.assertNotNull(signature.device)
                Assert.assertEquals(signature.device!!.deviceId, cryptoTestData.firstSession.credentials.deviceId)

                latch.countDown()
            }
        })
        mTestHelper.await(latch)

        cryptoTestData.clear(context)
    }

    /**
     * Check backup starts automatically if there is an existing and compatible backup
     * version on the homeserver.
     * - Create a backup version
     * - Restart alice session
     * -> The new alice session must back up to the same version
     */
    @Test
    fun testCheckAndStartKeyBackupWhenRestartingAMatrixSession() {
        // - Create a backup version
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        Assert.assertFalse(keysBackup.isEnabled)

        val keyBackupCreationInfo = prepareAndCreateKeyBackupData(keysBackup)

        Assert.assertTrue(keysBackup.isEnabled)

        // - Restart alice session
        // - Log Alice on a new device
        val aliceSession2 = mTestHelper.logIntoAccount(cryptoTestData.firstSession.myUserId, defaultSessionParams)

        cryptoTestData.clear(context)

        // -> The new alice session must back up to the same version
        val latch = CountDownLatch(1)
        keysBackup.addListener(object : KeysBackupStateManager.KeysBackupStateListener {
            override fun onStateChange(newState: KeysBackupStateManager.KeysBackupState) {
                // Check the backup completes
                if (keysBackup.state == KeysBackupStateManager.KeysBackupState.ReadyToBackUp) {
                    // Remove itself from the list of listeners
                    keysBackup.removeListener(this)

                    Assert.assertEquals(aliceSession2.crypto!!.keysBackup.currentBackupVersion, keyBackupCreationInfo.second)

                    latch.countDown()
                }
            }
        })
        mTestHelper.await(latch)

        aliceSession2.clear(context)
    }

    /**
     * Check WrongBackUpVersion state
     *
     * - Make alice back up her keys to her homeserver
     * - Create a new backup with fake data on the homeserver
     * - Make alice back up all her keys again
     * -> That must fail and her backup state must be disabled
     */
    @Test
    fun testBackupWhenAnotherBackupWasCreated() {
        // - Create a backup version
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        Assert.assertFalse(keysBackup.isEnabled)

        // - Make alice back up her keys to her homeserver
        prepareAndCreateKeyBackupData(keysBackup)

        Assert.assertTrue(keysBackup.isEnabled)

        // - Create a new backup with fake data on the homeserver
        val latch = CountDownLatch(1)
        keysBackup.createKeyBackupVersion(mCryptoTestHelper.createFakeMegolmBackupCreationInfo(), TestApiCallback(latch))
        mTestHelper.await(latch)

        // - Make alice back up all her keys again
        val latch2 = CountDownLatch(1)
        keysBackup.backupAllGroupSessions(object : KeysBackup.BackupProgress {
            override fun onProgress(backedUp: Int, total: Int) {
            }

        }, TestApiCallback(latch2, false))
        mTestHelper.await(latch)

        // -> That must fail and her backup state must be disabled
        Assert.assertEquals(keysBackup.state, KeysBackupStateManager.KeysBackupState.WrongBackUpVersion)
        Assert.assertFalse(keysBackup.isEnabled)

        cryptoTestData.clear(context)
    }

    /**
     * - Do an e2e backup to the homeserver
     * - Log Alice on a new device
     * - Post a message to have a new megolm session
     * - Try to backup all
     * -> It must fail
     * - Validate the old device from the new one
     * -> Backup should automatically enable on the new device
     * -> It must use the same backup version
     * - Try to backup all again
     * -> It must success
     */
    @Test
    fun testBackupAfterVerifyingADevice() {
        // - Create a backup version
        val context = InstrumentationRegistry.getContext()
        val cryptoTestData = mCryptoTestHelper.doE2ETestWithAliceAndBobInARoomWithEncryptedMessages(true)

        val keysBackup = cryptoTestData.firstSession.crypto!!.keysBackup

        // - Make alice back up her keys to her homeserver
        prepareAndCreateKeyBackupData(keysBackup)

        val latch = CountDownLatch(1)
        keysBackup.backupAllGroupSessions(object : KeysBackup.BackupProgress {
            override fun onProgress(backedUp: Int, total: Int) {

            }
        }, TestApiCallback(latch))
        mTestHelper.await(latch)

        val oldDeviceId = cryptoTestData.firstSession.credentials.deviceId
        val oldKeyBackupVersion = keysBackup.currentBackupVersion

        // - Log Alice on a new device
        val aliceSession2 = mTestHelper.logIntoAccount(cryptoTestData.firstSession.myUserId, defaultSessionParams)

        // TODO Enable crypto?

        // - Post a message to have a new megolm session
        aliceSession2.crypto!!.setWarnOnUnknownDevices(false)

        val room2 = aliceSession2.dataHandler.getRoom(cryptoTestData.roomId)

        mTestHelper.sendTextMessage(room2, "New key", 1)

        // - Try to backup all, it must fail
        val latch2 = CountDownLatch(1)
        keysBackup.backupAllGroupSessions(object : KeysBackup.BackupProgress {
            override fun onProgress(backedUp: Int, total: Int) {
            }

        }, object : TestApiCallback<Void?>(latch2, false) {
            override fun onSuccess(info: Void?) {
                Assert.fail("The backup must fail")
                super.onSuccess(info)
            }
        })
        mTestHelper.await(latch2)

        Assert.assertFalse(keysBackup.isEnabled)

        //  - Validate the old device from the new one
        val latch3 = CountDownLatch(1)
        aliceSession2.crypto!!.setDeviceVerification(MXDeviceInfo.DEVICE_VERIFICATION_VERIFIED, oldDeviceId, aliceSession2.myUserId, TestApiCallback(latch3))
        mTestHelper.await(latch3)

        // -> Backup should automatically enable on the new device
        val latch4 = CountDownLatch(1)
        keysBackup.addListener(object : KeysBackupStateManager.KeysBackupStateListener {
            override fun onStateChange(newState: KeysBackupStateManager.KeysBackupState) {
                // Check the backup completes
                if (keysBackup.state == KeysBackupStateManager.KeysBackupState.ReadyToBackUp) {
                    // Remove itself from the list of listeners
                    keysBackup.removeListener(this)

                    latch4.countDown()
                }
            }
        })
        mTestHelper.await(latch4)

        // -> It must use the same backup version
        Assert.assertEquals(oldKeyBackupVersion, aliceSession2.crypto!!.keysBackup.currentBackupVersion)

        val latch5 = CountDownLatch(1)
        aliceSession2.crypto!!.keysBackup.backupAllGroupSessions(null, TestApiCallback(latch5))
        mTestHelper.await(latch5)

        // -> It must success
        Assert.assertTrue(aliceSession2.crypto!!.keysBackup.isEnabled)

        aliceSession2.clear(context)
        cryptoTestData.clear(context)
    }

    /* ==========================================================================================
     * Private
     * ========================================================================================== */

    private fun prepareAndCreateKeyBackupData(keysBackup: KeysBackup): Pair<MegolmBackupCreationInfo, String> {
        var megolmBackupCreationInfo: MegolmBackupCreationInfo? = null
        val latch = CountDownLatch(1)
        keysBackup.prepareKeysBackupVersion(object : SuccessErrorCallback<MegolmBackupCreationInfo> {

            override fun onSuccess(info: MegolmBackupCreationInfo) {
                megolmBackupCreationInfo = info

                latch.countDown()
            }

            override fun onUnexpectedError(e: Exception) {
                Assert.fail(e.localizedMessage)

                latch.countDown()
            }
        })
        latch.await()

        assertNotNull(megolmBackupCreationInfo)

        assertFalse(keysBackup.isEnabled)

        val latch2 = CountDownLatch(1)

        // Create the version
        var version: String? = null
        keysBackup.createKeyBackupVersion(megolmBackupCreationInfo!!, object : TestApiCallback<KeysVersion>(latch2) {
            override fun onSuccess(info: KeysVersion) {
                assertNotNull(info)
                assertNotNull(info.version)

                version = info.version

                // Backup must be enable now
                assertTrue(keysBackup.isEnabled)

                super.onSuccess(info)
            }
        })
        mTestHelper.await(latch2)

        return Pair(megolmBackupCreationInfo!!, version!!)
    }
}