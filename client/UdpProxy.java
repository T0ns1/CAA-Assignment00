package client;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import crypto.CryptoUtils;
import crypto.PacketCipher;
import crypto.PacketCipherFactory;
import utils.SessionParameters;

public class UdpProxy {
	
	public static void main(String[] args) throws Exception {
		// Load properties configuration file
		Properties properties = new Properties();
		try (InputStream inputStream = new FileInputStream("config.properties")) {
			properties.load(inputStream);
		}
		
		InetSocketAddress inSocketAddress = parseSocketAddress(properties.getProperty("remote"));
		
		PublicKey serverPublicKey = CryptoUtils.loadPublicKeyFromCertificate(
				properties.getProperty("serverCertificateFile")
		);
		
		SessionParameters session = HandshakeClient.negotiate(
				properties.getProperty("serverHost"),
				Integer.parseInt(properties.getProperty("handshakePort")),
				properties.getProperty("cipher"),
				inSocketAddress.getHostString(),
				inSocketAddress.getPort(),
				serverPublicKey);
		
		PacketCipher packetCipher = PacketCipherFactory.fromSession(
				session.getCipherName(),
				session.getSessionKey(),
				session.getNoncePrefix()
		);
		
		String destinations = properties.getProperty("localdelivery");
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
				.map(s -> parseSocketAddress(s))
				.collect(Collectors.toSet());
		
		try (DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
	             DatagramSocket outSocket = new DatagramSocket()) {

			byte[] buffer = new byte[4 * 1024];

	        while (true) {
	        	DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
	            inSocket.receive(inPacket);
	            
	            byte[] plain = packetCipher.decrypt(inPacket.getData(), inPacket.getLength());
	            System.out.print(".");
	            for (SocketAddress outSocketAddress : outSocketAddressSet) {
	            	outSocket.send(new DatagramPacket(plain, plain.length, outSocketAddress));
	            }
	        }
		}
		
	}
	
	private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
    }

}
