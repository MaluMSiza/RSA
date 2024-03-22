import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import criptografia.AlgoritmoRSA;
import java.nio.charset.StandardCharsets;

public class TCPClient {
    private static final String SERVER_NAME = "192.168.0.193";
    private static final int SERVER_PORT = 12000;
    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            Socket clientSocket = new Socket(SERVER_NAME, SERVER_PORT);
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter outToServer = new PrintWriter(clientSocket.getOutputStream(), true);

            AlgoritmoRSA.RSAKeyPair aliceKeyPair = AlgoritmoRSA.generateRSAKeyPair(4096);
            outToServer.println(aliceKeyPair.getPublicKey());

            String bobPublicKeyStr = inFromServer.readLine();
            AlgoritmoRSA.RSAKey bobPublicKey = new AlgoritmoRSA.RSAKey(bobPublicKeyStr);

            System.out.print("Digite a mensagem para Bob: ");
            String messageToBob = scanner.nextLine();

            List<BigInteger> encryptedMessage = AlgoritmoRSA.encryptMessage(messageToBob, bobPublicKey);
            String encryptedMessageString = AlgoritmoRSA.joinBigIntegers(encryptedMessage);
            outToServer.println(encryptedMessageString);

            String modifiedSentence = inFromServer.readLine();
            List<BigInteger> modifiedSentenceList = new ArrayList<>();
            for (String num : modifiedSentence.split(",")) {
                modifiedSentenceList.add(new BigInteger(num));
            }
            String decryptedMessage = AlgoritmoRSA.decryptMessage(modifiedSentenceList, aliceKeyPair.getPrivateKey());
            System.out.println("Mensagem decifrada: " + decryptedMessage);

            byte[] decryptedBytes = decryptedMessage.getBytes(StandardCharsets.UTF_8);
            String decryptedUTF8 = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("Mensagem decifrada em UTF-8: " + decryptedUTF8);

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
