package seguridad20222_cliente;
import java.net.Socket;
import java.util.Scanner;

public class ClienteMain {

    private static Socket sc;
	private static String host = "localhost";
	private static int puerto = 4030;
    public static void main(String[] args) {

        System.out.println("Starting client System");
        Scanner s = new Scanner(System.in);
        System.out.println("Ingrese el numero de clientes concurrentes a crear: ");
        int numClients = s.nextInt();
        s.close();
        try {
            for (int i = 0; i < numClients; i++) {
                sc = new Socket(host, puerto);        
                System.out.println("Creating socket: done");
                String id = String.valueOf(i);
                ClienteThread c = new ClienteThread(sc, id);
                c.start();
            }
            System.out.println("All clients created");
            
        } catch (Exception e) { e.printStackTrace(); }
    }

}
