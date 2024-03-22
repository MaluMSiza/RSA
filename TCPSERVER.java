import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class TCPSERVER {
    private static final int SERVER_PORT = 12000;
    private static final List<Integer> firstPrimesList = new ArrayList<>();

    static {
        firstPrimesList.add(2);
        firstPrimesList.add(3);
        firstPrimesList.add(5);
    }

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            System.out.println("Servidor TCP esperando por conexões na porta " + SERVER_PORT);
            Socket connectionSocket = serverSocket.accept();
            System.out.println("Conexão estabelecida com " + connectionSocket.getRemoteSocketAddress());

            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            PrintWriter outToClient = new PrintWriter(connectionSocket.getOutputStream(), true);

            RSAKeyPair bobKeyPair = generateRSAKeyPair(4096);
            outToClient.println(bobKeyPair.getPublicKey());

            String alicePublicKeyStr = inFromClient.readLine();
            RSAKey alicePublicKey = new RSAKey(alicePublicKeyStr);

            String messageFromAlice = inFromClient.readLine();
            List<BigInteger> messageList = new ArrayList<>();
            for (String num : messageFromAlice.split(",")) {
                messageList.add(new BigInteger(num));
            }

            String decryptedMessage = decryptMessage(messageList, bobKeyPair.getPrivateKey());
            System.out.println("Mensagem decifrada: " + decryptedMessage);

            String uppercaseMessage = decryptedMessage.toUpperCase();

            List<BigInteger> encryptedMessage = encryptMessage(uppercaseMessage, alicePublicKey);
            outToClient.println(joinBigIntegers(encryptedMessage));

            connectionSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class RSAKey {
        private final BigInteger exponent;
        private final BigInteger modulus;

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

    private static class RSAKeyPair {
        private final RSAKey publicKey;
        private final RSAKey privateKey;

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

    private static RSAKeyPair generateRSAKeyPair(int bits) {
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

    private static BigInteger getLowLevelPrime(int bits, Random rand) {
        while (true) {
            BigInteger pc = new BigInteger(bits, rand);
            if (isPrime(pc)) {
                return pc;
            }
        }
    }

    private static boolean isPrime(BigInteger n) {
        for (int i = 0; i < firstPrimesList.size(); i++) {
            if (n.mod(BigInteger.valueOf(firstPrimesList.get(i))).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return n.isProbablePrime(100);
    }

    private static String decryptMessage(List<BigInteger> message, RSAKey privateKey) {
        StringBuilder decryptedMessage = new StringBuilder();
        for (BigInteger num : message) {
            BigInteger decryptedNum = num.modPow(privateKey.getExponent(), privateKey.getModulus());
            decryptedMessage.append((char) decryptedNum.intValue());
        }
        return decryptedMessage.toString();
    }

    private static List<BigInteger> encryptMessage(String message, RSAKey publicKey) {
        List<BigInteger> encryptedMessage = new ArrayList<>();
        for (char c : message.toCharArray()) {
            encryptedMessage.add(BigInteger.valueOf(c).modPow(publicKey.getExponent(), publicKey.getModulus()));
        }
        return encryptedMessage;
    }

    private static String joinBigIntegers(List<BigInteger> list) {
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
