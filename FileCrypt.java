import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class FileCrypt {
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); 
        return keyGen.generateKey();
    }

    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        String filePath = "gagan.txt";
        SecretKey key = generateKey();
        
        // Encrypt file
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        byte[] encryptedData = encrypt(fileData, key);
        Files.write(Paths.get("encryptedFile.aes"), encryptedData);
        
        // Decrypt file
        byte[] encryptedFileData = Files.readAllBytes(Paths.get("encryptedFile.aes"));
        byte[] decryptedData = decrypt(encryptedFileData, key);
        Files.write(Paths.get("decryptedFile.txt"), decryptedData);
        
        System.out.println("Encryption and Decryption done!");
    }
}
