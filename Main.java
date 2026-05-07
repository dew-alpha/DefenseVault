import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class Main {
    private static final int SALT_LENGTH = 16;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("======================================");
        System.out.println("    DefenseDataVault CLI Started      ");
        System.out.println("======================================");
        System.out.println("Available Commands:");
        System.out.println("  encrypt <filename> <password>");
        System.out.println("  decrypt <filename.vault> <password>");
        System.out.println("  exit");
        
        while (true) {
            System.out.print("\nVault> ");
            String input = scanner.nextLine().trim();
            
            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down the vault...");
                break;
            }
            
            if (input.isEmpty()) continue;

            String[] parts = input.split("\\s+");
            if (parts.length != 3) {
                System.out.println("Error: Invalid command format. Requires precisely 3 arguments.");
                continue;
            }
            
            String command = parts[0];
            String filename = parts[1];
            String password = parts[2];
            
            try {
                if (command.equalsIgnoreCase("encrypt")) {
                    encryptFile(filename, password);
                } else if (command.equalsIgnoreCase("decrypt")) {
                    decryptFile(filename, password);
                } else {
                    System.out.println("Error: Unknown command '" + command + "'");
                }
            } catch (SecurityException e) {
                System.out.println("Security Error: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("System Error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private static void encryptFile(String filename, String password) throws Exception {
        File file = new File(filename);
        if (!file.exists()) {
            System.out.println("Error: File not found -> " + filename);
            return;
        }

        // 1. Generate a random 16-byte salt for key derivation
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        
        // 2. Derive the SecretKey
        SecretKey key = KeyManager.generateKeyFromPassword(password, salt);
        
        // 3. Read the file completely using FileInputStream
        byte[] plaintext;
        try (FileInputStream fis = new FileInputStream(file)) {
            plaintext = fis.readAllBytes(); 
        }
        
        // 4. Calculate Integrity Hash
        byte[] hash = IntegrityChecker.calculateDataHash(plaintext);
        
        // 5. Encrypt data
        EncryptionEngine engine = new EncryptionEngine();
        byte[] encryptedPayload = engine.encrypt(plaintext, key);
        
        // 6. Save back out using FileOutputStream
        String vaultFilename = filename + ".vault";
        try (FileOutputStream fos = new FileOutputStream(vaultFilename)) {
            // Write Salt (16 bytes) -> Hash (32 bytes) -> Encrypted Payload (IV + Ciphertext)
            fos.write(salt);
            fos.write(hash);
            fos.write(encryptedPayload);
        }
        
        System.out.println("Success! File encrypted and saved to -> " + vaultFilename);
    }
    
    private static void decryptFile(String filename, String password) throws Exception {
        File file = new File(filename);
        if (!file.exists()) {
            System.out.println("Error: File not found -> " + filename);
            return;
        }
        
        // 1. Read the vaulted file completely using FileInputStream
        byte[] vaultedData;
        try (FileInputStream fis = new FileInputStream(file)) {
            vaultedData = fis.readAllBytes();
        }
        
        // Minimum size check: Salt(16) + Hash(32) + IV(12) = 60 bytes
        if (vaultedData.length < SALT_LENGTH + 32 + 12) {
            throw new IllegalArgumentException("Invalid or corrupted vault file.");
        }
        
        // 2. Extract Salt (first 16 bytes)
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(vaultedData, 0, salt, 0, SALT_LENGTH);
        
        // 3. Extract Hash (next 32 bytes)
        byte[] storedHash = new byte[32];
        System.arraycopy(vaultedData, SALT_LENGTH, storedHash, 0, 32);
        
        // 4. Extract Encrypted Payload
        int payloadLength = vaultedData.length - SALT_LENGTH - 32;
        byte[] encryptedPayload = new byte[payloadLength];
        System.arraycopy(vaultedData, SALT_LENGTH + 32, encryptedPayload, 0, payloadLength);
        
        // 5. Derive the SecretKey
        SecretKey key = KeyManager.generateKeyFromPassword(password, salt);
        
        // 6. Decrypt
        EncryptionEngine engine = new EncryptionEngine();
        byte[] plaintext;
        try {
            plaintext = engine.decrypt(encryptedPayload, key);
        } catch (javax.crypto.AEADBadTagException e) {
             throw new SecurityException("Incorrect password or tampered data (GCM validation failed).");
        }
        
        // 7. Verify Integrity Hash
        byte[] computedHash = IntegrityChecker.calculateDataHash(plaintext);
        if (!Arrays.equals(storedHash, computedHash)) {
            throw new SecurityException("Mismatched Fingerprint! Integrity check failed.");
        }
        
        // 8. Write safely to output file using FileOutputStream
        String outputFilename = filename.endsWith(".vault") ? filename.substring(0, filename.length() - 6) : filename + ".decrypted";
        File outFile = new File(outputFilename);
        if(outFile.exists()) {
             outputFilename = "decrypted_" + outputFilename;
        }
        
        try (FileOutputStream fos = new FileOutputStream(outputFilename)) {
            fos.write(plaintext);
        }
        
        System.out.println("Success! File decrypted and saved to -> " + outputFilename);
    }
}
