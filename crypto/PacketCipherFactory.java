package crypto;

public class PacketCipherFactory {
	public static PacketCipher fromSession(String cipherName, byte[] keyBytes, byte[] noncePrefixBytes) {
        switch (cipherName.trim().toUpperCase()) {
            case "CHACHA20_POLY1305" -> { return new ChaCha20Poly1305PacketCipher(keyBytes, noncePrefixBytes); }
            case "AES_GCM" -> { return new AesGcmPacketCipher(keyBytes, noncePrefixBytes); }
            case "OTP_PRG" -> { return new OtpPrgPacketCipher(keyBytes); }
            default -> throw new IllegalArgumentException("Unsupported cipher: " + cipherName);
        }
    }
}
