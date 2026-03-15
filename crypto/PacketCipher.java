package crypto;

/**
 * Interface for a ciphered packet
 * @author Antonio Mendes
 *
 */
public interface PacketCipher {
	/**
	 * 
	 * @param plain plaintext to encrypt
	 * @param len number of plaintext bytes to encrypt
	 * @return encrypted packet byte array
	 * @throws Exception if encryption fails
	 */
    byte[] encrypt(byte[] plain, int len) throws Exception;
    /**
     * 
     * @param packet encrypted packet
     * @param len number of encrypted bytes to decrypt
     * @return decrypted plaintext
     * @throws Exception if decryption fails or authentication fails
     */
    byte[] decrypt(byte[] packet, int len) throws Exception;
}
