package com.poplavkov;

import org.openjdk.jmh.annotations.*;

import javax.crypto.*;
import java.util.concurrent.TimeUnit;

public class AESBenchmark {

    @State(Scope.Thread)
    public static class AESState {

        @Setup(Level.Trial)
        public void doSetup() throws Exception {
            AESEncryptCipher = Cipher.getInstance("AES");
            AESDecryptCipher = Cipher.getInstance("AES");
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);
            SecretKey key = generator.generateKey();
            AESEncryptCipher.init(Cipher.ENCRYPT_MODE, key);
            AESDecryptCipher.init(Cipher.DECRYPT_MODE, key);
            bytes = Util.generateRandomBytes();
            bytesToDecrypt = AESEncryptCipher.doFinal(bytes);
        }

        Cipher AESEncryptCipher;
        Cipher AESDecryptCipher;
        byte[] bytes;
        byte[] bytesToDecrypt;
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        return state.AESEncryptCipher.doFinal(state.bytes);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] decryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        return state.AESDecryptCipher.doFinal(state.bytesToDecrypt);
    }

    @Benchmark @BenchmarkMode(Mode.AverageTime) @OutputTimeUnit(TimeUnit.MILLISECONDS) @Fork(1)
    public byte[] encryptAndDecryptAES(AESState state) throws BadPaddingException, IllegalBlockSizeException {
        byte[] bytes =  state.AESEncryptCipher.doFinal(state.bytes);
        return state.AESDecryptCipher.doFinal(bytes);
    }

}