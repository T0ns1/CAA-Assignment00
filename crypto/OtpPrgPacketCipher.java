package crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * OTP-style packet cipher using a deterministic pseudorandom generator.
 *
 * Packet format:
 * [seq:8][ciphertext:n]
 *
 * Keystream derivation:
 *   packetSeed = HMAC-SHA256(sessionKey, "OTP_PRG" || seq)
 *   block_i    = HMAC-SHA256(packetSeed, i)
 *
 * This provides confidentiality only.
 * It does NOT provide authenticity or integrity.
 */
public class OtpPrgPacketCipher implements PacketCipher {
    private static final int SEQ_LEN = 8;
    private static final byte[] LABEL = "OTP_PRG".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final byte[] sessionKey;
    private long sendSeq = 0;

    // Simple duplicate/replay protection state.
    // This accepts out-of-order packets within a 64-packet window.
    private long highestSeqSeen = -1;
    private long replayWindow = 0L;

    public OtpPrgPacketCipher(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("OTP_PRG key must not be empty");
        }
        this.sessionKey = Arrays.copyOf(keyBytes, keyBytes.length);
    }

    @Override
    public byte[] encrypt(byte[] plain, int len) throws Exception {
        if (len < 0 || len > plain.length) {
            throw new IllegalArgumentException("Invalid plaintext length: " + len);
        }

        long seq = sendSeq++;
        byte[] keystream = generateKeystream(seq, len);

        byte[] ciphertext = xor(plain, keystream, len);

        ByteBuffer out = ByteBuffer.allocate(SEQ_LEN + ciphertext.length);
        out.putLong(seq);
        out.put(ciphertext);
        return out.array();
    }

    @Override
    public byte[] decrypt(byte[] packet, int len) throws Exception {
        if (len < SEQ_LEN) {
            throw new IllegalArgumentException("Packet too short");
        }

        ByteBuffer in = ByteBuffer.wrap(packet, 0, len);
        long seq = in.getLong();

        if (isReplayOrTooOld(seq)) {
            throw new SecurityException("Replay, duplicate, or too-old packet rejected");
        }

        int cipherLen = len - SEQ_LEN;
        byte[] ciphertext = new byte[cipherLen];
        in.get(ciphertext);

        byte[] keystream = generateKeystream(seq, cipherLen);
        byte[] plain = xor(ciphertext, keystream, cipherLen);

        markSeen(seq);
        return plain;
    }

    private byte[] generateKeystream(long seq, int len) throws Exception {
        byte[] packetSeed = hmac(sessionKey, ByteBuffer.allocate(LABEL.length + 8)
                .put(LABEL)
                .putLong(seq)
                .array());

        byte[] out = new byte[len];
        int pos = 0;
        int counter = 0;

        while (pos < len) {
            byte[] block = hmac(packetSeed, ByteBuffer.allocate(4).putInt(counter).array());
            int copy = Math.min(block.length, len - pos);
            System.arraycopy(block, 0, out, pos, copy);
            pos += copy;
            counter++;
        }

        return out;
    }

    private byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private byte[] xor(byte[] input, byte[] keystream, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (input[i] ^ keystream[i]);
        }
        return out;
    }

    /**
     * 64-packet replay window:
     * - exact duplicates rejected
     * - old packets outside the window rejected
     * - out-of-order packets inside the window accepted
     */
    private boolean isReplayOrTooOld(long seq) {
        if (highestSeqSeen == -1) {
            return false;
        }

        if (seq > highestSeqSeen) {
            return false;
        }

        long delta = highestSeqSeen - seq;
        if (delta >= 64) {
            return true;
        }

        long mask = 1L << delta;
        return (replayWindow & mask) != 0;
    }

    private void markSeen(long seq) {
        if (highestSeqSeen == -1) {
            highestSeqSeen = seq;
            replayWindow = 1L;
            return;
        }

        if (seq > highestSeqSeen) {
            long shift = seq - highestSeqSeen;
            if (shift >= 64) {
                replayWindow = 1L;
            } else {
                replayWindow = (replayWindow << shift) | 1L;
            }
            highestSeqSeen = seq;
            return;
        }

        long delta = highestSeqSeen - seq;
        if (delta < 64) {
            replayWindow |= (1L << delta);
        }
    }
}