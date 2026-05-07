import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class EncryptionEngine {

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // Standard and most secure tag length
    private static final int IV_LENGTH_BYTES = 12; // Recommended length for GCM

    /**
     * Encrypts the provided plaintext using AES/GCM.
     * Generates a random 12-byte IV for each encryption and prepends it to the
     * output.
     *
     * @param plaintext The data to encrypt.
     * @param key       The SecretKey to use for encryption.
     * @return A byte array containing the 12-byte IV followed by the ciphertext.
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        // Generate a cryptographically secure random 12-byte IV
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        // doFinal automatically appends the authentication tag in GCM mode
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend the IV to the ciphertext.
        // This makes decrypting easier since the IV will travel with the data.
        ByteBuffer byteBuffer = ByteBuffer.allocate(IV_LENGTH_BYTES + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);

        return byteBuffer.array();
    }

    /**
     * Decrypts AES/GCM encrypted data. Expects the IV to be prepended to the data.
     *
     * @param encryptedData The byte array containing the IV followed by the
     *                      ciphertext.
     * @param key           The SecretKey to use for decryption.
     * @return The decrypted plaintext as a byte array.
     */
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        if (encryptedData.length < IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Encrypted data is too short to contain a valid IV.");
        }

        // Initialize GCM parameters by pointing directly to the IV at the start of the
        // array
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(
                GCM_TAG_LENGTH_BITS, encryptedData, 0, IV_LENGTH_BYTES);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        // Decrypt the data (skipping the first 12 bytes which contain the IV)
        return cipher.doFinal(encryptedData, IV_LENGTH_BYTES, encryptedData.length - IV_LENGTH_BYTES);
    }
}
