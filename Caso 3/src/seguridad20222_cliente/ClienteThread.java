package seguridad20222_cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClienteThread extends Thread {

    private Socket sc;
    private String id;
    private ClienteSecurityFunctions csf;
    private PublicKey publicKey;
    private PrintWriter ac;
    private BufferedReader dc;

    ClienteThread(Socket socket, String id) {
        this.sc = socket;
        this.id = id;
        this.csf = new ClienteSecurityFunctions();
    }

    @Override
	public void run() {
		
		String linea;
	
	    try {
			
            this.ac = new PrintWriter(sc.getOutputStream() , true);
            this.publicKey = csf.read_kplus("Caso 3/datos_asim_srv.pub", this.id);
            this.dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

            // 1. Se envia el mensaje de inicio seguro
            ac.println("SECURE INIT");

            // 2. Se reciben los parametros para diffie-helman

            // Recibe g
            linea = dc.readLine();
            BigInteger g = new BigInteger(linea);
            
            // Recibe p
            linea = dc.readLine();
            BigInteger p = new BigInteger(linea);

            // Recibe g2x
            linea = dc.readLine();
            BigInteger g2x = new BigInteger(linea);

            // Recibe la firma y procede a verificarla
            String signature = dc.readLine();
            System.out.println(signature);

            //Se usa el metodo proporcionado para pasar la firma de String a byte[]
            byte[] signatureBytes = str2byte(signature);

            //4. Se verifica la firma usando el mensaje concatenado de g, p y g2x
            String completeDiffieHelman = g.toString() + "," + p.toString() + "," + g2x;
            System.out.println("Cliente " + this.id + " verificando firma de " + completeDiffieHelman);
            try {
                boolean  signatureVerified = csf.checkSignature(publicKey, signatureBytes, completeDiffieHelman);
                if (signatureVerified) {
                    System.out.println("La firma fue verificada correctamente");

                    // 5. Se envia OK dado que fue verificada la firma
                    ac.println("OK");

                    //6a. Generamos g2y teniendo en cuenta los pasos anteriores
                    SecureRandom r = new SecureRandom();
                    int x = Math.abs(r.nextInt());
                    Long longx = Long.valueOf(x);
                    BigInteger bix = BigInteger.valueOf(longx);
                    BigInteger g2yCliente = G2X(g, bix, p);

                    //6b. Enviamos g2y al servidor
                    ac.println(g2yCliente.toString());

                    //7a. Calculamos la llave maestra y el g2y del servidor
                    BigInteger g2yServidor = g2x.mod(p);
                    BigInteger llaveMaestra = calcular_llave_maestra(g2yServidor, bix, p);
                    String llaveMaestraString = llaveMaestra.toString();
                    System.out.println("Cliente " + id + " - llave maestra: " + llaveMaestraString);
                    
                    // Generamos la llave simetrica para el cifrado y para el HMAC
                    SecretKey ck_client = csf.csk1(llaveMaestraString);
                    SecretKey ck_mac = csf.csk2(llaveMaestraString);

                    byte[] iv1 = generateIvBytes();
                    String iv1String = byte2str(iv1);
                    IvParameterSpec iv1Spec = new IvParameterSpec(iv1);

                    //8. Generamos la consulta
                    int consulta = ThreadLocalRandom.current().nextInt();
                    String consultaString = Integer.toString(consulta);
                    byte[] consultaBytes = consultaString.getBytes();
                    System.out.println("Cliente " + id + " - consulta: " + consultaString);
                    
                    //8a. Encriptamos la consulta
                    byte[] consultaEncriptada = csf.senc(consultaBytes, ck_client, iv1Spec, this.id);
                    byte[] hashConsulta = csf.hmac(consultaBytes, ck_mac);
                    String consultaEncriptadaString = byte2str(consultaEncriptada);
                    String hashConsultaString = byte2str(hashConsulta);

                    //8b. Enviamos la consulta encriptada
                    ac.println(consultaEncriptadaString);
                    ac.println(hashConsultaString);
                    ac.println(iv1String);

                    //12. Recibimos la respuesta del servidor
                    linea = dc.readLine();

                    if (linea.equals("OK")) {
                        
                        String str_consulta = dc.readLine();
                        String str_mac = dc.readLine();
                        String str_iv2 = dc.readLine();
                        byte[] byte_consulta = str2byte(str_consulta);
                        byte[] byte_mac = str2byte(str_mac);
                        
                        byte[] iv2 = str2byte(str_iv2);
                        IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);

                        //12a. Desencriptamos la respuesta
                        byte[] desencriptada = csf.sdec(byte_consulta, ck_client, ivSpec2);
                        boolean verificar = csf.checkInt(desencriptada, ck_mac, byte_mac);
                        System.out.println("Cliente " + this.id + " Integrity check: " + verificar);  
                        if (verificar) {
                            String respuestaDesencriptadaString = new String(desencriptada, StandardCharsets.UTF_8);
                            System.out.println("Cliente " + this.id + " - respuesta: " + respuestaDesencriptadaString);
                            System.out.println("Consulta enviada por el cliente " + this.id + ": " + consultaString);
                            ac.println("OK");
                            System.out.println("Cliente " + this.id + " - Cerrando conexion con un resultado de ejecucion exitoso");
                        } else {
                            System.out.println("Cliente " + this.id + " - respuesta: " + " No se pudo verificar la integridad de la respuesta");
                            ac.println("ERROR");
                        }

                    } else {
                        System.out.println("Cliente " + id + " - Error en la respuesta del servidor");
                    }
    
                } else {
                    System.out.println("La firma no pudo ser verificada");

                    // 5. Se envia ERROR dado que no fue verificada la firma correctamente
                    ac.println("ERROR");
                }
            } catch (SignatureException s) {
                s.printStackTrace();
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
	
	private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}

    private BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}

    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
}
