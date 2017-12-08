package com.poplavkov;

import org.openjdk.jmh.annotations.*;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

public class AESBenchmark {

    @State(Scope.Thread)
    public static class AESState {

        @Setup(Level.Invocation)
        public void doSetup() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
            AESEncryptCipher = Cipher.getInstance("AES");
            AESDecryptCipher = Cipher.getInstance("AES");
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);
            SecretKey key = generator.generateKey();
            AESEncryptCipher.init(Cipher.ENCRYPT_MODE, key);
            AESDecryptCipher.init(Cipher.DECRYPT_MODE, key);
            bytes = Util.generateRandomBytes();
        }

        Cipher AESEncryptCipher;
        Cipher AESDecryptCipher;
        byte[] bytes;
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        return state.AESEncryptCipher.doFinal(state.bytes);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] decryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        return state.AESDecryptCipher.doFinal(state.bytes);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptAndDecryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        byte[] bytes =  state.AESEncryptCipher.doFinal(state.bytes);
        return state.AESDecryptCipher.doFinal(bytes);
    }

}