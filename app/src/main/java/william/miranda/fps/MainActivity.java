package william.miranda.fps;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_NAME = "KEY_NAME";

    private TextView summary;
    private TextView authStatus;

    private KeyguardManager keyguardManager;
    private FingerprintManager fingerprintManager;

    private KeyStore keyStore;
    private Cipher cipher;
    private FingerprintManager.CryptoObject crypto;

    FingerprintManager.AuthenticationCallback callback = new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            updateText("onAuthenticationError: " + errorCode + " - " + errString);
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            updateText("onAuthenticationHelp: " + helpCode + " - " + helpString);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            updateText("onAuthenticationSucceeded");
        }

        @Override
        public void onAuthenticationFailed() {
            updateText("onAuthenticationFailed");
        }
    };

    private CancellationSignal.OnCancelListener cancelListener = new CancellationSignal.OnCancelListener() {
        @Override
        public void onCancel() {
            Log.d("BRUTUS", "onCancel");
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        //Check whether the device has a fingerprint sensor
        if (!fingerprintManager.isHardwareDetected()) {
            // If a fingerprint sensor isn’t available, then inform the user that they’ll be unable to use your app’s fingerprint functionality//
            Toast.makeText(this, "Your device doesn't support fingerprint authentication", Toast.LENGTH_LONG).show();
            return;
        }
        //Check whether the user has granted your app the USE_FINGERPRINT permission//
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            // If your app doesn't have this permission, then display the following text//
            Toast.makeText(this, "Please enable the fingerprint permission", Toast.LENGTH_LONG).show();
            return;
        }

        //Check that the user has registered at least one fingerprint//
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            // If the user hasn’t configured any fingerprints, then display the following message//
            Toast.makeText(this, "No fingerprint configured. Please register at least one fingerprint in your device's Settings", Toast.LENGTH_LONG).show();
            return;
        }

        generateKey();
        cipherInit();
        crypto = new FingerprintManager.CryptoObject(cipher);

        final CancellationSignal canc = new CancellationSignal();
        canc.setOnCancelListener(cancelListener);

        findViewById(R.id.start_auth).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                fingerprintManager.authenticate(crypto, canc, 0, callback, null);
                updateText("");
            }
        });

        summary = (TextView) findViewById(R.id.summary);
        authStatus = (TextView) findViewById(R.id.auth_status);
    }

    @TargetApi(Build.VERSION_CODES.M)
    protected void generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            e.printStackTrace();
        }
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }
        try {
            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException |
                InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    //init the Cipher
    @TargetApi(Build.VERSION_CODES.M)
    public boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7); //get instance
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key); //Cipher initialization using secret key
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    void updateText(String text) {
        summary.setText(text);
    }
}
