import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class DefenseDataVault {

    private final EncryptionEngine encryptionEngine;

    public DefenseDataVault() {
        this.encryptionEngine = new EncryptionEngine();
    }

    /**
     * Secures a file by calculating its SHA-256 hash, encrypting the file data,
     * and combining them together.
     * 
     * Vault Format: [32-byte SHA-256 Plaintext Hash] + [12-byte IV] + [Ciphertext]
     *
     * @param inputFile           The path to the original raw file.
     * @param encryptedOutputFile The path where the vaulted file should be saved.
     * @param key                 The SecretKey.
     */
    public void secureFile(Path inputFile, Path encryptedOutputFile, SecretKey key) throws Exception {
        // 1. Calculate the plaintext SHA-256 hash to act as our integrity &
        // verification fingerprint
        byte[] plaintextHash = IntegrityChecker.calculateFileHash(inputFile);

        // 2. Read the file & encrypt the payload
        byte[] plaintext = Files.readAllBytes(inputFile);
        byte[] encryptedPayload = encryptionEngine.encrypt(plaintext, key);

        // 3. Package the Hash alongside the encrypted payload
        // The encryptedPayload already effectively contains the IV and Ciphertext.
        ByteBuffer vaultBuffer = ByteBuffer.allocate(plaintextHash.length + encryptedPayload.length);
        vaultBuffer.put(plaintextHash);
        vaultBuffer.put(encryptedPayload);

        // 4. Save the fully vaulted data to the output file
        Files.write(encryptedOutputFile, vaultBuffer.array());
    }

    /**
     * Extracts a vaulted file, decrypts it, and verifies the extracted plaintext
     * against the stored SHA-256 hash.
     *
     * @param vaultedFile The path to the secured vault file.
     * @param key         The SecretKey.
     * @return The fully decrypted and verified plaintext bytes.
     */
    public byte[] extractFile(Path vaultedFile, SecretKey key) throws Exception {
        byte[] vaultedData = Files.readAllBytes(vaultedFile);

        // Minimum length: 32 bytes (SHA-256) + 12 bytes (IV)
        if (vaultedData.length < 32 + 12) {
            throw new IllegalArgumentException(
                    "Vaulted file is tampered, corrupted, or not in valid DefenseVault format.");
        }

        // 1. Extract the 32-byte SHA-256 plaintext hash
        byte[] storedHash = new byte[32];
        System.arraycopy(vaultedData, 0, storedHash, 0, 32);

        // 2. Extract the remaining encrypted payload
        byte[] encryptedPayload = new byte[vaultedData.length - 32];
        System.arraycopy(vaultedData, 32, encryptedPayload, 0, encryptedPayload.length);

        // 3. Decrypt the payload
        byte[] decryptedPlaintext = encryptionEngine.decrypt(encryptedPayload, key);

        // 4. Verification Check: Re-hash the decrypted data and see if it perfectly
        // matches the stored hash
        byte[] computedHash = IntegrityChecker.calculateDataHash(decryptedPlaintext);
        if (!Arrays.equals(storedHash, computedHash)) {
            throw new SecurityException("Mismatched Fingerprint! The decrypted file does not match the original hash.");
        }

        return decryptedPlaintext;
    }
}
