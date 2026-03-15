package crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class CryptoUtils {
	private static final SecureRandom RANDOM = new SecureRandom();

    public static byte[] randomBytes(int size) {
        byte[] b = new byte[size];
        RANDOM.nextBytes(b);
        return b;
    }

    public static PublicKey loadPublicKeyFromCertificate(String certFile) throws Exception {
        try (InputStream in = new FileInputStream(certFile)) {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(in);
            return cert.getPublicKey();
        }
    }

    public static PrivateKey loadPrivateKeyFromKeystore(String keystoreFile, String keystorePassword,
                                                        String alias, String keyPassword) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(keystoreFile)) {
            ks.load(in, keystorePassword.toCharArray());
        }
        return (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
    }

    public static byte[] rsaEncrypt(byte[] plain, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaep);
        return cipher.doFinal(plain);
    }

    public static byte[] rsaDecrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaep);
        return cipher.doFinal(ciphertext);
    }

    public static void writeByteArray(DataOutputStream out, byte[] data) throws Exception {
        out.writeInt(data.length);
        out.write(data);
    }

    public static byte[] readByteArray(DataInputStream in) throws Exception {
        int len = in.readInt();
        byte[] data = new byte[len];
        in.readFully(data);
        return data;
    }
}
