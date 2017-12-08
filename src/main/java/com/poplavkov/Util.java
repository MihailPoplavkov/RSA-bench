package com.poplavkov;

import java.util.Random;

public class Util {

    static byte[] generateRandomBytes(int capacity) {
        Random random = new Random();
        byte[] bytes = new byte[capacity];
        random.nextBytes(bytes);
        return bytes;
    }

    static byte[] generateRandomBytes() {
        return generateRandomBytes(16384);
    }
}
