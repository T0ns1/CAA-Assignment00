package utils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class SessionBlob {
	private final byte[] sessionKey;
    private final byte[] noncePrefix;

    public SessionBlob(byte[] sessionKey, byte[] noncePrefix) {
        this.sessionKey = sessionKey;
        this.noncePrefix = noncePrefix;
    }

    public byte[] getSessionKey() { return sessionKey; }
    public byte[] getNoncePrefix() { return noncePrefix; }

    public byte[] serialize() throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        out.writeInt(sessionKey.length);
        out.write(sessionKey);
        out.writeInt(noncePrefix.length);
        out.write(noncePrefix);
        out.flush();
        return baos.toByteArray();
    }

    public static SessionBlob deserialize(byte[] data) throws IOException {
        DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(data));
        int keyLen = in.readInt();
        byte[] sessionKey = new byte[keyLen];
        in.readFully(sessionKey);
        int nonceLen = in.readInt();
        byte[] noncePrefix = new byte[nonceLen];
        in.readFully(noncePrefix);
        return new SessionBlob(sessionKey, noncePrefix);
    }
}
