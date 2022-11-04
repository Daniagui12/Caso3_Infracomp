package seguridad20222_cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

public class ClienteThread extends Thread {

    private Socket sc;
    private String id;
    private PublicKey publicKey;
    private ClienteSecurityFunctions csf;

    ClienteThread(Socket socket, String id) {
        this.sc = socket;
        this.id = id;
        this.csf = new ClienteSecurityFunctions();
    }

    @Override
	public void run() {
		
		String linea;
	

	    try {

			PublicKey publicKey = csf.read_kplus("Caso 3/datos_asim_srv.pub", this.id);
			PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));
				    	
            ac.println("SECURE INIT");
            linea = dc.readLine();
            System.out.println("Cliente " + id + ": recibido " + linea + " - done");
    		

	        sc.close();
	    } catch (Exception e) { e.printStackTrace(); }

	}
        
}
