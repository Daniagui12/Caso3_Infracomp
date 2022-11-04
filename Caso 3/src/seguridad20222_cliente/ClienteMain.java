package seguridad20222_cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClienteMain {

    private static Socket sc;
	private static String host = "localhost";
	private static int puerto = 4030;
    public static void main(String[] args) {
        
        System.out.println("Starting client");
        try {

            sc = new Socket(host, puerto);
            System.out.println("Creating socket: done");
            ClienteThread ct = new ClienteThread(sc, "1");
            ct.start();

        } catch (Exception e) { e.printStackTrace(); }
    }
    
}
