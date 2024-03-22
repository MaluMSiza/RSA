import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import criptografia.AlgoritmoRSA;

public class TCPServer {
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

            AlgoritmoRSA.RSAKeyPair bobKeyPair = AlgoritmoRSA.generateRSAKeyPair(4096);
            outToClient.println(bobKeyPair.getPublicKey());

            String alicePublicKeyStr = inFromClient.readLine();
            AlgoritmoRSA.RSAKey alicePublicKey = new AlgoritmoRSA.RSAKey(alicePublicKeyStr);

            String messageFromAlice = inFromClient.readLine();
            List<BigInteger> messageList = new ArrayList<>();
            for (String num : messageFromAlice.split(",")) {
                messageList.add(new BigInteger(num));
            }

            String decryptedMessage = AlgoritmoRSA.decryptMessage(messageList, bobKeyPair.getPrivateKey());
            System.out.println("Mensagem decifrada: " + decryptedMessage);

            String uppercaseMessage = decryptedMessage.toUpperCase();

            List<BigInteger> encryptedMessage = AlgoritmoRSA.encryptMessage(uppercaseMessage, alicePublicKey);
            outToClient.println(AlgoritmoRSA.joinBigIntegers(encryptedMessage));

            connectionSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
