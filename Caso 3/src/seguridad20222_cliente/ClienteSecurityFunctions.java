package seguridad20222_cliente;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClienteSecurityFunctions {
	private String algoritmo_simetrico = "AES/CBC/PKCS5Padding";
	private String algoritmo_asimetrico = "RSA";
	public long tiempoCifrado = 0;
	public long tiempoHMAC = 0;
	public long tiempoFirma = 0;
    
    public boolean checkSignature(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
		long startTime = System.nanoTime();
        publicSignature.initVerify(publica);
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        boolean isCorrect = publicSignature.verify(firma);
		long endTime = System.nanoTime();
		tiempoFirma += (endTime - startTime);
        return isCorrect;
    }
    
    public byte[] aenc(PublicKey publica, String mensaje) throws Exception {        
        Cipher encryptCipher = Cipher.getInstance(algoritmo_asimetrico);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publica);
        byte[] cipherText = encryptCipher.doFinal(mensaje.getBytes());
        return cipherText;
    }
    
    public String adec(byte[] cifrado, PrivateKey privada) throws Exception {
        Cipher decriptCipher = Cipher.getInstance(algoritmo_asimetrico);
        decriptCipher.init(Cipher.DECRYPT_MODE, privada);
        String decipheredMessage = new String(decriptCipher.doFinal(cifrado), StandardCharsets.UTF_8);
        System.out.println(decipheredMessage);
        return decipheredMessage;
    }
    
	public byte[] hmac(byte[] msg, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance("HMACSHA256");
		long start = System.nanoTime();
		mac.init(key);
		byte[] bytes = mac.doFinal(msg);
		long end = System.nanoTime();
		tiempoHMAC += (end - start);
		return bytes;
	}

	public boolean checkInt(byte[] msg, SecretKey key, byte [] hash ) throws Exception
	{
		byte [] nuevo = hmac(msg, key);
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if (nuevo[i] != hash[i]) return false;
		}
		return true;
	}
    
    public SecretKey csk1(String semilla) throws Exception {
    	byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
    	MessageDigest digest = MessageDigest.getInstance("SHA-512");
    	byte[] encodedhash = digest.digest(byte_semilla);
    	byte[] encoded1 = new byte[32];
		for (int i = 0; i < 32 ; i++) {
			encoded1[i] = encodedhash[i];
		}
		SecretKey sk = null;
		sk = new SecretKeySpec(encoded1,"AES");	
		return sk;
	}
    
    public SecretKey csk2(String semilla) throws Exception {
    	byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
    	MessageDigest digest = MessageDigest.getInstance("SHA-512");
    	byte[] encodedhash = digest.digest(byte_semilla);
    	byte[] encoded2 = new byte[32];
		for (int i = 32; i < 64 ; i++) {
			encoded2[i-32] = encodedhash[i];
		}
		SecretKey sk = null;
		sk = new SecretKeySpec(encoded2,"AES");	
		return sk;
	}
	
	public byte[] senc (byte[] msg, SecretKey key, IvParameterSpec iv, String id) throws Exception {
		Cipher decifrador = Cipher.getInstance(algoritmo_simetrico); 
		long start = System.nanoTime();
		decifrador.init(Cipher.ENCRYPT_MODE, key, iv); 
		byte[] tmp = decifrador.doFinal(msg);
	    long end = System.nanoTime();      
	    System.out.println(id+" --- Elapsed Time for SYM encryption in nano seconds: "+ (end-start));   
		tiempoCifrado += (end-start);			
		return tmp;
	}
	
	public byte[] sdec (byte[] msg, SecretKey key, IvParameterSpec iv) throws Exception {
		Cipher decifrador = Cipher.getInstance(algoritmo_simetrico); 
		decifrador.init(Cipher.DECRYPT_MODE, key, iv); 
		return decifrador.doFinal(msg);
	}
	
	public PublicKey read_kplus(String nombreArchivo, String id) {
		FileInputStream is1;
		PublicKey pubkey = null;
		System.out.println(id+nombreArchivo);
		try {
			is1 = new FileInputStream(nombreArchivo);
			File f = new File(nombreArchivo);		
			byte[] inBytes1 = new byte[(int)f.length()];
			is1.read(inBytes1);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(inBytes1);
			pubkey = kf.generatePublic(publicKeySpec);
			is1.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pubkey;
	}

	public long getTiempoCifrado() {
		return tiempoCifrado;
	}

	public long getTiempoHMAC() {
		return tiempoHMAC;
	}

	public long getTiempoFirma() {
		return tiempoFirma;
	}
}