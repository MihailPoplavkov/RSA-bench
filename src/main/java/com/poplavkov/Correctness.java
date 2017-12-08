package com.poplavkov;

import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.*;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class Correctness {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String str = "HELLO WORLD FROM RSAaaaaaaa ";
        for (int i = 0; i < 10; i++) {
            str = str + str;
        }
        System.out.println(str);
        System.out.println("-------------------------------------------------------");
        System.out.println(encryptAndDecryptWithRSA(str));
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
        Cipher RSAEncryptCipher = Cipher.getInstance("RSA");
        Cipher RSADecryptCipher = Cipher.getInstance("RSA");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512);
        KeyPair keyPair = generator.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();
        RSAEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        RSADecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = s.getBytes();
        int blockSize = 512 / 8;
        bytes = doFinalWithRSA(bytes, RSAEncryptCipher, blockSize - 11);
        bytes = doFinalWithRSA(bytes, RSADecryptCipher, blockSize);
        String s1 = new String(bytes);
        System.out.println(s.length());
        System.out.println(s1.length());
        return s1;
    }

    private static byte[] doFinalWithRSA(byte[] input, Cipher cipher, int blockSize) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int length = input.length;
        //keySize / 8 - 11;
        int blockCount = length / blockSize + (length % blockSize == 0 ? 0 : 1);
        List<Byte> list = new ArrayList<>(blockCount * 64);
        int from = 0;
        int inputLen = blockSize;
        for (int i = 0; i < blockCount; i++) {
            for (byte b: cipher.doFinal(input, from, inputLen)) {
                list.add(b);
            }
            from += blockSize;
            if (from + inputLen > length) {
                inputLen = length - from;
            }
        }
        return ArrayUtils.toPrimitive(list.toArray(new Byte[0]));
    }
}
