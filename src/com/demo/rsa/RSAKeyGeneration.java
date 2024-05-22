package com.demo.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAKeyGeneration {
	
	private static Logger log = LoggerFactory.getLogger(RSAKeyGeneration.class);
	private String localStoragePath = "D:\\data";
	private File publicKeyFile = new File(localStoragePath+"\\publicKey.pem");
	private File privateKeyFile = new File(localStoragePath+"\\privateKey.pem");
	
	public void rsaKeyGenerate() {
		try {
			// Initialize the key pair generator
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // You can specify the key size
            
            // 	Generate the key pair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            // Print the keys in Base64 encoded format
            System.out.println("Public Key: " + java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            System.out.println("Private Key: " + java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            
            // 	Save the keys to files
            saveKeyToFile(publicKeyFile,"RSA PUBLIC KEY",publicKey.getEncoded());
            saveKeyToFile(privateKeyFile,"RSA PRIVATE KEY",privateKey.getEncoded());
            
            System.out.println("success");
		}catch(Exception ex) {
			ex.printStackTrace();
			log.error("key generation error : "+ex.getMessage());
		}
	}
	
	private static void saveKeyToFile(File fileName, String header, byte[] key) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            String encodedKey = Base64.getEncoder().encodeToString(key);
            String pemKey = "-----BEGIN " + header + "-----\n"
                          + encodedKey
                          + "\n-----END " + header + "-----\n";
            fos.write(pemKey.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	
	private PublicKey getPublicKeyFromFile() {
		log.info("access for get the public key from publicKeyFile");
		try {
			Path filePath = Paths.get(localStoragePath + File.separator + "publicKey.pem").toAbsolutePath().normalize();
			// Read the file line by line and concatenate the lines
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Remove whitespace and other unnecessary characters
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("-----")) {
                        sb.append(line);
                    }
                }
            }
            // Convert the bytes to a string (assuming the key is stored as a string)
	        String publicKeyString = new String(sb.toString());
	        
	        // Remove any whitespace characters (e.g., newline characters)
	        publicKeyString = publicKeyString.trim();
	        
	        // Decode the Base64 encoded key bytes
	        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
	        
	        // Generate the PublicKey object from the key bytes
	        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		} catch(Exception ex) {
			ex.printStackTrace();
			log.error("Error from get the public key from public Key file");
		}
		return null;
	}
	
	private PrivateKey getPrivateKeyFromFile() {
		log.info("access for get the priavte key from privateKeyFile");
		try {
			Path filePath = Paths.get(localStoragePath + File.separator + "privateKey.pem").toAbsolutePath().normalize();
			// Read the file line by line and concatenate the lines
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Remove whitespace and other unnecessary characters
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("-----")) {
                        sb.append(line);
                    }
                }
            }
            // Convert the bytes to a string (assuming the key is stored as a string)
	        String privateKeyString = new String(sb.toString());
	        
	        // Remove any whitespace characters (e.g., newline characters)
	        privateKeyString = privateKeyString.trim();
	        
	        // Decode the Base64 encoded key bytes
	        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
	        
	        // 	Generate the PublicKey object from the key bytes
	        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		} catch(Exception ex) {
			ex.printStackTrace();
			log.error("Error from get the private key from private Key file");
		}
		return null;
	}
	
	private String encryptMessage(String message, PublicKey publicKey) {
        try {
            // Initialize the cipher with the public key for encryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encrypt the message
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	private String decryptMessage(String encryptedMessage, PrivateKey privateKey) {
        try {
            // Initialize the cipher with the private key for decryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decode the Base64 encoded encrypted message
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);

            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	public static void main(String[] args) {
		String testData = "Hello World";
		System.out.println("Data Before Encryption - "+testData);
		RSAKeyGeneration key = new RSAKeyGeneration();
		
		// generate key
		key.rsaKeyGenerate();
		
		// encrypted message
		PublicKey publicKey = key.getPublicKeyFromFile();
		String encryptedMsg = key.encryptMessage(testData, publicKey);
		System.out.println("Encrypted Message - "+encryptedMsg);
		
		// decrypted message
		PrivateKey privateKey = key.getPrivateKeyFromFile();
		String finalData = key.decryptMessage(encryptedMsg, privateKey);
		System.out.println("Final Data After decryption - "+finalData);
	}
}
