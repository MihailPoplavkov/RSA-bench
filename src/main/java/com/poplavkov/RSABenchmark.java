package com.poplavkov;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.*;
import java.security.*;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public class RSABenchmark {

    @State(Scope.Thread)
    public static class RSAState {

        @Setup(Level.Invocation)
        public void doSetup() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
            AESEncryptCipher = Cipher.getInstance("RSA");
            AESDecryptCipher = Cipher.getInstance("RSA");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(512);
            KeyPair keyPair = generator.generateKeyPair();
            Key publicKey = keyPair.getPublic();
            Key privateKey = keyPair.getPrivate();
            AESEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            AESDecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byteBlocks = split(Util.generateRandomBytes(), 512);

        }

        Cipher AESEncryptCipher;
        Cipher AESDecryptCipher;
        byte[][] byteBlocks;
    }

//    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    public byte[] encryptRSA(RSAState state) throws BadPaddingException, IllegalBlockSizeException {
//        return state.AESEncryptCipher.doFinal(state.bytes);
//    }
//
//    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    public byte[] decryptRSA(RSAState state) throws BadPaddingException, IllegalBlockSizeException {
//        return state.AESDecryptCipher.doFinal(state.bytes);
//    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public int encryptAndDecryptRSA(RSAState state) throws BadPaddingException, IllegalBlockSizeException {
        int size = 0;
        for (byte[] b: state.byteBlocks) {
            byte[] bytes = state.AESEncryptCipher.doFinal(b);
            bytes = state.AESDecryptCipher.doFinal(bytes);
            size += bytes.length;
        }
        return size;
    }

    private static byte[][] split(byte[] bytes, int keySize) {
        int blockSize = keySize / 8 - 11;
        int rows = bytes.length / blockSize;
        if (bytes.length % blockSize != 0) rows++;
        byte[][] result = new byte[rows][blockSize];
        int from = 0;
        int to = blockSize;
        for (int i = 0; i < rows; i++) {
            if (to > bytes.length) to = bytes.length;
            result[i] = Arrays.copyOfRange(bytes, from, to);
            from = to;
            to += blockSize;
        }
        return result;
    }
}
