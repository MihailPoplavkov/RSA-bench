package com.poplavkov;

import javax.crypto.*;
import java.security.*;

public class Correctness {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println(encryptAndDecryptWithAES("HELLO WORLD FROM AES"));
        System.out.println(encryptAndDecryptWithRSA("HELLO WORLD FROM RSA"));
    }

    private static String encryptAndDecryptWithAES(String s) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher AESEncryptCipher = Cipher.getInstance("AES");
        Cipher AESDecryptCipher = Cipher.getInstance("AES");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey key = generator.generateKey();
        AESEncryptCipher.init(Cipher.ENCRYPT_MODE, key);
        AESDecryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] bytes = AESEncryptCipher.doFinal(s.getBytes());
        return new String(AESDecryptCipher.doFinal(bytes));
    }

    private static String encryptAndDecryptWithRSA(String s) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher AESEncryptCipher = Cipher.getInstance("RSA");
        Cipher AESDecryptCipher = Cipher.getInstance("RSA");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512);
        KeyPair keyPair = generator.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();
        AESEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        AESDecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = AESEncryptCipher.doFinal(s.getBytes());
        return new String(AESDecryptCipher.doFinal(bytes));
    }
}
