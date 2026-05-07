import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class KeyManager {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    /**
     * Generates a SecretKey from a given password and salt using
     * PBKDF2WithHmacSHA256.
     *
     * @param password The user-provided password.
     * @param salt     A unique, random salt to prevent rainbow table attacks.
     * @return A SecretKey suitable for AES encryption.
     */
    public static SecretKey generateKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

        // Generate the raw secret key from PBKDF2
        SecretKey tmp = factory.generateSecret(spec);

        // Wrap the raw key data in an AES SecretKeySpec
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}
