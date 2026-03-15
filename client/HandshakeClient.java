package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PublicKey;

import crypto.CryptoUtils;
import utils.SessionBlob;
import utils.SessionParameters;

public class HandshakeClient {
	
	public static SessionParameters negotiate(String serverHost, int handshakePort,
			String cipherName, String proxyUdpHost, int proxyUdpPort,
			PublicKey serverPublicKey) throws Exception {
		
		byte[] sessionKey = CryptoUtils.randomBytes(32);
		byte[] noncePrefix = CryptoUtils.randomBytes(4);
		
		SessionBlob blob = new SessionBlob(sessionKey, noncePrefix);
		byte[] encryptedBlob = CryptoUtils.rsaEncrypt(blob.serialize(), serverPublicKey);
		
		try (Socket socket = new Socket(serverHost, handshakePort)) {
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			
			out.writeUTF(cipherName);
			out.writeUTF(proxyUdpHost);
			out.writeInt(proxyUdpPort);
			CryptoUtils.writeByteArray(out, encryptedBlob);
			out.flush();
			
			if (!in.readBoolean()) throw new IllegalStateException(in.readUTF());
			in.readUTF();
			
			return new SessionParameters(cipherName, sessionKey, noncePrefix, proxyUdpHost, proxyUdpPort);
		}
		
	}
}
