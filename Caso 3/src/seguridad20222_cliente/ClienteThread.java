package seguridad20222_cliente;

import java.math.BigInteger;
import java.net.Socket;

public class ClienteThread extends Thread {

    private Socket socket;
    private String id;
	private String dlg;	
	private BigInteger p;
	private BigInteger g;
	private ClienteSecurityFunctions f;	
	private int mod;

    ClienteThread(Socket socket, String id, String dlg, BigInteger p, BigInteger g, int mod) {
        this.socket = socket;
        this.id = id;
        this.dlg = dlg;
        this.p = p;
        this.g = g;
        this.mod = mod;
        f = new ClienteSecurityFunctions();
    }

}
