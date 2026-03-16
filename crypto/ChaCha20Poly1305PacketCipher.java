package crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChaCha20Poly1305PacketCipher implements PacketCipher{
	
	private static final int NONCE_LEN = 12;
    private static final int SEQ_LEN = 8;
    
    private final SecretKey key;
    private final byte[] noncePrefix;
    private long sendSeq;
    private long lastReceivedSeq;
    
    public ChaCha20Poly1305PacketCipher(byte[] keyBytes, byte[] noncePrefixBytes) {
    	this.key = new SecretKeySpec(keyBytes, "ChaCha20");
        this.noncePrefix = Arrays.copyOf(noncePrefixBytes, noncePrefixBytes.length);
        
        this.sendSeq = 0;
        this.lastReceivedSeq = -1;
    }
	
	@Override
	public byte[] encrypt(byte[] plain, int len) throws Exception {
		long seq = sendSeq++;
        byte[] nonce = buildNonce(seq);
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
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
        if (seq <= lastReceivedSeq) throw new SecurityException("Replay or dupe rejected");
        
        byte[] nonce = buildNonce(seq);
        
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
        cipher.updateAAD(ByteBuffer.allocate(SEQ_LEN).putLong(seq).array());
        
        byte[] ciphertext = new byte[len - SEQ_LEN];
        in.get(ciphertext);
        
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
