package jp.kentan.dev.androidkeystoreexample

import android.os.Build
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

    private companion object {
        const val TAG = "MainActivity"

        const val KEY_ALIAS = "example_key"
        const val CIPHER_TYPE = "RSA/ECB/PKCS1Padding"

        val UTF_8: Charset = Charset.forName("UTF-8")
    }

    private lateinit var keyStore: KeyStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            createKeyIfNeed(keyStore)

            this.keyStore = keyStore
        } catch (e: Exception) {
            e.printStackTrace()
        }

        encrypt_button.setOnClickListener {
            val text = edit_text.text
            if (text.isNullOrBlank()) {
                text_input_layout.error = "入力して下さい"
                return@setOnClickListener
            }

            encrypted_text.text = encrypt(text.toString())
        }

        decrypt_button.setOnClickListener {
            val text = encrypted_text.text
            edit_text.setText(decrypt(text.toString()))
        }
    }

    private fun createKeyIfNeed(keyStore: KeyStore) {
        // 鍵が生成済みか確認
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return
        }

        val start = Calendar.getInstance()
        val end = Calendar.getInstance().apply {
            add(Calendar.YEAR, 100)
        }

        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setCertificateSubject(X500Principal("CN=$KEY_ALIAS"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setKeyValidityStart(start.time)
                .setKeyValidityEnd(end.time)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build()
        } else {
            KeyPairGeneratorSpec.Builder(this)
                .setAlias(KEY_ALIAS)
                .setSubject(X500Principal("CN=$KEY_ALIAS"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
        }

        KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun encrypt(text: String): String? {
        if (text.isEmpty()) {
            Log.e(TAG, "Empty decrypt text")
            return null
        }

        try {
            val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey

            val cipher = Cipher.getInstance(CIPHER_TYPE, "AndroidOpenSSL").apply {
                init(Cipher.ENCRYPT_MODE, publicKey)
            }

            val bytes = cipher.doFinal(text.toByteArray(UTF_8))

            return Base64.encodeToString(bytes, Base64.DEFAULT)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt", e)
        }

        return null
    }

    private fun decrypt(text: String?): String? {
        if (text.isNullOrEmpty()) {
            Log.e(TAG, "Empty encrypt text")
            return null
        }

        try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null)

            val cipher = Cipher.getInstance(CIPHER_TYPE).apply {
                init(Cipher.DECRYPT_MODE, privateKey)
            }

            val bytes = cipher.doFinal(Base64.decode(text, Base64.DEFAULT))

            return String(bytes, UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt", e)
        }

        return null
    }
}
