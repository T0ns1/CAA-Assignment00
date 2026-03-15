package server;

import crypto.CryptoUtils;
import crypto.PacketCipher;
import crypto.PacketCipherFactory;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.util.Properties;
import utils.SessionParameters;

public class StreamServer {
	static public void main( String []args ) throws Exception {
		if (args.length != 1) {
			System.out.println("Use: java StreamServer <movie>");
			System.exit(-1);
		}
		
		Properties properties = new Properties();
		try (InputStream configIn = new FileInputStream("config.properties")) {
			properties.load(configIn);
		}
		
		PrivateKey serverPrivateKey = CryptoUtils.loadPrivateKeyFromKeystore(
				properties.getProperty("keystoreFile"),
				properties.getProperty("keystorePassword"),
				properties.getProperty("keyAlias"),
				properties.getProperty("keyPassword")
		);
		
		HandshakeServer handshakeServer = new HandshakeServer(
				Integer.parseInt(properties.getProperty("handshakePort")),
				serverPrivateKey
		);
		
		System.out.println("Awaiting connection...");
		SessionParameters session = handshakeServer.waitForSession();
		System.out.println("Session established");
		
		PacketCipher packetCipher = PacketCipherFactory.fromSession(
				session.getCipherName(),
				session.getSessionKey(),
				session.getNoncePrefix()
		);
		
		try (DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
			 DatagramSocket s = new DatagramSocket()) {
			
			byte[] buff = new byte[4 * 1024];
			InetSocketAddress addr = new InetSocketAddress(session.getProxyHost(), session.getProxyPort());
			DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
			
			int size;
			int csize = 0;
			int count = 0;
	 		long time;
	 		
	 		long t0 = System.nanoTime(); // Ref. time 
			long q0 = 0;
			
			while (g.available() > 0) {
				size = g.readShort(); // size of the frame
				csize=csize+size;
				time = g.readLong(); // timestamp of the frame
				if ( count == 0 ) q0 = time; // ref. time in the stream
				count += 1;
				g.readFully(buff, 0, size);
				
				byte[] securePayload = packetCipher.encrypt(buff, size);
				p.setData(securePayload, 0, securePayload.length);
				p.setSocketAddress(addr);
				
				long t = System.nanoTime(); // what time is it?
				
				// Decision about the right time to transmit
				Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
				
				s.send(p);
				
				System.out.print( ":" );
			}
		}
	}
}
