package crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmPacketCipher implements PacketCipher{
	private static final int NONCE_LEN = 12;
    private static final int SEQ_LEN = 8;
    
    private final SecretKey key;
    private final byte[] noncePrefix;
    private long sendSeq;
    private long lastReceivedSeq;
    
    public AesGcmPacketCipher(byte[] keyBytes, byte[] noncePrefixBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
        this.noncePrefix = Arrays.copyOf(noncePrefixBytes, noncePrefixBytes.length);
        
        this.sendSeq = 0;
        this.lastReceivedSeq = -1;
    }
	
	@Override
	public byte[] encrypt(byte[] plain, int len) throws Exception {
		long seq = sendSeq++;
        byte[] nonce = buildNonce(seq);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(ByteBuffer.allocate(SEQ_LEN).putLong(seq).array());
        byte[] ciphertext = cipher.doFinal(plain, 0, len);

        ByteBuffer out = ByteBuffer.allocate(SEQ_LEN + ciphertext.length);
        out.putLong(seq).put(ciphertext);
        return out.array();
	}

	@Override
	public byte[] decrypt(byte[] packet, int len) throws Exception {
		ByteBuffer in = ByteBuffer.wrap(packet, 0, len);
        long seq = in.getLong();
        if (seq <= lastReceivedSeq) throw new SecurityException("Replay/Dupe rejected");

	byte[] nonce = buildNonce(seq);

        byte[] ciphertext = new byte[len - SEQ_LEN];
        in.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(ByteBuffer.allocate(SEQ_LEN).putLong(seq).array());

        byte[] plain = cipher.doFinal(ciphertext);
        lastReceivedSeq = seq;
        return plain;
	}
	
	private byte[] buildNonce(long seq) {
        ByteBuffer bb = ByteBuffer.allocate(NONCE_LEN);
        bb.put(noncePrefix).putLong(seq);
        return bb.array();
    }

}
