package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;

import crypto.CryptoUtils;
import utils.SessionBlob;
import utils.SessionParameters;

public class HandshakeServer {
	
	private final int port;
	private final PrivateKey serverPrivateKey;
	
	public HandshakeServer(int port, PrivateKey serverPrivateKey) {
		this.port = port;
		this.serverPrivateKey = serverPrivateKey;
	}
	
	public SessionParameters waitForSession() throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(port);
				Socket socket = serverSocket.accept()) {
			
			DataInputStream in = new DataInputStream(socket.getInputStream());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			
			String cipherName = in.readUTF();
			String proxyUdpHost = in.readUTF();
			int proxyUdpPort = in.readInt();
			
			byte[] encryptedBlob = CryptoUtils.readByteArray(in);
			byte[] decryptedBlob = CryptoUtils.rsaDecrypt(encryptedBlob, serverPrivateKey);
			SessionBlob blob = SessionBlob.deserialize(decryptedBlob);
			
			out.writeBoolean(true);
			out.writeUTF("OK");
			out.flush();
			
			return new SessionParameters(cipherName, blob.getSessionKey(), blob.getNoncePrefix(), proxyUdpHost, proxyUdpPort);
		}
	}

}
