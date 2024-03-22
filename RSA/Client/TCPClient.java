import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import criptografia.AlgoritmoRSA;

public class TCPClient {
    private static final String SERVER_NAME = "192.168.0.193";
    private static final int SERVER_PORT = 12000;

    public static void main(String[] args) {
        try {
            Socket clientSocket = new Socket(SERVER_NAME, SERVER_PORT);
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter outToServer = new PrintWriter(clientSocket.getOutputStream(), true);

            AlgoritmoRSA.RSAKeyPair aliceKeyPair = AlgoritmoRSA.generateRSAKeyPair(4096);
            outToServer.println(aliceKeyPair.getPublicKey());

            String bobPublicKeyStr = inFromServer.readLine();
            AlgoritmoRSA.RSAKey bobPublicKey = new AlgoritmoRSA.RSAKey(bobPublicKeyStr);

            String messageToBob = "Fábio Henrique Cabrini"; // Change your message here
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

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
