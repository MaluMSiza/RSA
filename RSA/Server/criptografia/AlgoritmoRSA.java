package criptografia;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class AlgoritmoRSA {
    public static final List<Integer> firstPrimesList = new ArrayList<>();

    static {
        firstPrimesList.add(2);
        firstPrimesList.add(3);
        firstPrimesList.add(5);
    }

    public static class RSAKey {
        public final BigInteger exponent;
        public final BigInteger modulus;

        public RSAKey(BigInteger exponent, BigInteger modulus) {
            this.exponent = exponent;
            this.modulus = modulus;
        }

        public RSAKey(String keyString) {
            String[] parts = keyString.split(",");
            this.exponent = new BigInteger(parts[0]);
            this.modulus = new BigInteger(parts[1]);
        }

        public BigInteger getExponent() {
            return exponent;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public String toString() {
            return exponent + "," + modulus;
        }
    }

    public static class RSAKeyPair {
        public final RSAKey publicKey;
        public final RSAKey privateKey;

        public RSAKeyPair(RSAKey publicKey, RSAKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public RSAKey getPublicKey() {
            return publicKey;
        }

        public RSAKey getPrivateKey() {
            return privateKey;
        }
    }

    public static RSAKeyPair generateRSAKeyPair(int bits) {
        Random rand = new Random();
        BigInteger p, q, n, phi, e, d;
        do {
            p = getLowLevelPrime(bits, rand);
            q = getLowLevelPrime(bits, rand);
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            e = BigInteger.valueOf(65537); // Common public exponent
            d = e.modInverse(phi);
        } while (!e.gcd(phi).equals(BigInteger.ONE));
        RSAKey publicKey = new RSAKey(e, n);
        RSAKey privateKey = new RSAKey(d, n);
        return new RSAKeyPair(publicKey, privateKey);
    }

    public static BigInteger getLowLevelPrime(int bits, Random rand) {
        while (true) {
            BigInteger pc = new BigInteger(bits, rand);
            if (isPrime(pc)) {
                return pc;
            }
        }
    }

    public static boolean isPrime(BigInteger n) {
        for (int i = 0; i < firstPrimesList.size(); i++) {
            if (n.mod(BigInteger.valueOf(firstPrimesList.get(i))).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return n.isProbablePrime(100);
    }

    public static String decryptMessage(List<BigInteger> message, RSAKey privateKey) {
        StringBuilder decryptedMessage = new StringBuilder();
        for (BigInteger num : message) {
            BigInteger decryptedNum = num.modPow(privateKey.getExponent(), privateKey.getModulus());
            decryptedMessage.append((char) decryptedNum.intValue());
        }
        return decryptedMessage.toString();
    }

    public static List<BigInteger> encryptMessage(String message, RSAKey publicKey) {
        List<BigInteger> encryptedMessage = new ArrayList<>();
        for (char c : message.toCharArray()) {
            encryptedMessage.add(BigInteger.valueOf(c).modPow(publicKey.getExponent(), publicKey.getModulus()));
        }
        return encryptedMessage;
    }

    public static String joinBigIntegers(List<BigInteger> list) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            result.append(list.get(i));
            if (i < list.size() - 1) {
                result.append(",");
            }
        }
        return result.toString();
    }
}
