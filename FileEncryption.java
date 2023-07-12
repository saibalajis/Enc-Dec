package org.crypt;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class FileEncryptionExample {
    private static final String ALGORITHM = "AES";

    public static void encryptFiles(String key, String inputDirectory, String outputDirectory)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);

        File inputDir = new File(inputDirectory);
        File[] files = inputDir.listFiles();
        if (files == null) {
            System.out.println("No files found in the input directory.");
            return;
        }
        for (File inputFile : files) {
            if (!inputFile.isFile()) {
                continue;
            }

            String outputFile = outputDirectory + File.separator + inputFile.getName() + ".enc";
            encryptFile(secretKeySpec, inputFile.getPath(), outputFile);
        }

        System.out.println("Encryption completed successfully.");
    }

    public static void decryptFiles(String key, String inputDirectory, String outputDirectory)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);

        File inputDir = new File(inputDirectory);
        File[] files = inputDir.listFiles();
        if (files == null) {
            System.out.println("No files found in the input directory.");
            return;
        }

        for (File inputFile : files) {
            if (!inputFile.isFile()) {
                continue;
            }

            String outputFile = outputDirectory + File.separator + inputFile.getName().replace(".enc", "");
            decryptFile(secretKeySpec, inputFile.getPath(), outputFile);
        }

        System.out.println("Decryption completed successfully.");
    }

    private static SecretKeySpec generateSecretKeySpec(String key) throws NoSuchAlgorithmException {
        byte[] keyBytes = key.getBytes();
        byte[] keyBytesFinal = new byte[16];
        System.arraycopy(keyBytes, 0, keyBytesFinal, 0, Math.min(keyBytes.length, keyBytesFinal.length));
        return new SecretKeySpec(keyBytesFinal, ALGORITHM);
    }

    private static void encryptFile(SecretKeySpec secretKeySpec, String inputFile, String outputFile)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    private static void decryptFile(SecretKeySpec secretKeySpec, String inputFile, String outputFile)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        } 
    }

    public static void main(String[] args) {
        String key = "Secretkey"; 
        String inputDirectory = "E:\\User\\Crypto\\src";
        String outputDirectory = "E:\\User\\Crypto\\Enc";

        try {
            encryptFiles(key, inputDirectory, outputDirectory);
           // decryptFiles(key, inputDirectory, outputDirectory); 
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException e) {
            e.printStackTrace();
        }
    }
}