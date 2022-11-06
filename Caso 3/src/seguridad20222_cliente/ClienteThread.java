package seguridad20222_cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;

public class ClienteThread extends Thread {

    private Socket sc;
    private String id;
    private ClienteSecurityFunctions csf;

    ClienteThread(Socket socket, String id) {
        this.sc = socket;
        this.id = id;
        this.csf = new ClienteSecurityFunctions();
    }

    @Override
	public void run() {
		
        String linea;
		BigInteger g;
        BigInteger p;
        BigInteger g2x;
        String completeDiffieHelman;
        String signature;
        byte[] signatureBytes;
        boolean signatureVerified;
	

	    try {

			PublicKey publicKey = csf.read_kplus("Caso 3/datos_asim_srv.pub", this.id);
			PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));
				    	
            ac.println("SECURE INIT");

            // Recibe g
            linea = dc.readLine();
            g = new BigInteger(linea);
            
            // Recibe p
            linea = dc.readLine();
            p = new BigInteger(linea);

            // Recibe g2x
            linea = dc.readLine();
            g2x = new BigInteger(linea);

            // Recibe la firma y procede a verificarla
            signature = dc.readLine();
            System.out.println(signature);

            //Se usa el metodo proporcionado para pasar la firma de String a byte[]
            signatureBytes = str2byte(signature);

            //Se verifica la firma usando el mensaje concatenado de g, p y g2x
            completeDiffieHelman = g.toString() + "," + p.toString() + "," + g2x;
            try {
                signatureVerified = csf.checkSignature(publicKey, signatureBytes, completeDiffieHelman);
                if (signatureVerified) {
                    System.out.println("La firma fue verificada correctamente");
                    ac.println("OK");
    
                } else {
                    System.out.println("La firma no pudo ser verificada");
                    ac.println("ERROR");
                }
            } catch (Exception e) {
                e.printStackTrace();
                ac.println("ERROR");
            }

	        sc.close();
	    } catch (Exception e) { e.printStackTrace(); }

	}    

    public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
}
