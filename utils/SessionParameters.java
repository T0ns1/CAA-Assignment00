package utils;

import java.util.Arrays;

public class SessionParameters {
	private final String cipherName;
    private final byte[] sessionKey;
    private final byte[] noncePrefix;
    private final String proxyHost;
    private final int proxyPort;

    public SessionParameters(String cipherName, byte[] sessionKey, byte[] noncePrefix,
                             String proxyHost, int proxyPort) {
        this.cipherName = cipherName;
        this.sessionKey = Arrays.copyOf(sessionKey, sessionKey.length);
        this.noncePrefix = Arrays.copyOf(noncePrefix, noncePrefix.length);
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
    }

    public String getCipherName() { return cipherName; }
    public byte[] getSessionKey() { return Arrays.copyOf(sessionKey, sessionKey.length); }
    public byte[] getNoncePrefix() { return Arrays.copyOf(noncePrefix, noncePrefix.length); }
    public String getProxyHost() { return proxyHost; }
    public int getProxyPort() { return proxyPort; }
}
