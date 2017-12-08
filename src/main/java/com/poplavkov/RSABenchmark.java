package com.poplavkov;

import org.apache.commons.lang3.ArrayUtils;
import org.openjdk.jmh.annotations.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class RSABenchmark {

    @State(Scope.Thread)
    public static class RSAState {

        @Setup(Level.Trial)
        public void doSetup() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            RSAEncryptCipher = Cipher.getInstance("RSA");
            RSADecryptCipher = Cipher.getInstance("RSA");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            int keySize = 512;
            generator.initialize(keySize);
            KeyPair keyPair = generator.generateKeyPair();
            Key publicKey = keyPair.getPublic();
            Key privateKey = keyPair.getPrivate();
            RSAEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            RSADecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            bytes = Util.generateRandomBytes();
            blockSize = keySize / 8;
            bytesToDecrypt = doFinalWithRSA(bytes, RSAEncryptCipher, blockSize - 11);
        }

        Cipher RSAEncryptCipher;
        Cipher RSADecryptCipher;
        byte[] bytes;
        byte[] bytesToDecrypt;
        int blockSize;
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptRSA(RSAState state) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return doFinalWithRSA(state.bytes, state.RSAEncryptCipher, state.blockSize - 11);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] decryptRSA(RSAState state) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return doFinalWithRSA(state.bytesToDecrypt, state.RSADecryptCipher, state.blockSize);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptAndDecryptRSA(RSAState state) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] bytes = doFinalWithRSA(state.bytes, state.RSAEncryptCipher, state.blockSize - 11);
        return doFinalWithRSA(bytes, state.RSADecryptCipher, state.blockSize);
    }

    private static byte[] doFinalWithRSA(byte[] input, Cipher cipher, int blockSize) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int length = input.length;
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
