import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

public class IntegrityChecker {

    private static final String HASH_ALGORITHM = "SHA-256";

    /**
     * Calculates the SHA-256 hash of a file on disk.
     * Streams the file to handle large files efficiently.
     *
     * @param filePath The path to the file.
     * @return The 32-byte SHA-256 hash.
     */
    public static byte[] calculateFileHash(Path filePath) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        
        try (InputStream fis = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        
        return digest.digest();
    }

    /**
     * Calculates the SHA-256 hash of a byte array in memory.
     *
     * @param data The byte array to hash.
     * @return The 32-byte SHA-256 hash.
     */
    public static byte[] calculateDataHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        return digest.digest(data);
    }
}
