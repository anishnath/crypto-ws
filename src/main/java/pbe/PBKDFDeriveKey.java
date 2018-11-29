package pbe;



import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


import cacerts.Utils;
import pojo.EncodedMessage;

/**
 * 
 * @author Anish Nath Demo @8gwifi.org
 *
 */
public class PBKDFDeriveKey {
	
	

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public  EncodedMessage hashPassword(String cipher, final String password,  final int iterations,
			final int keyLength) throws Exception {

		try {
			final byte[] salt = getNextSalt();
			SecretKeyFactory skf = SecretKeyFactory.getInstance(cipher);
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			
			EncodedMessage encodedMessage = new EncodedMessage();
			
			encodedMessage.setBase64Decoded( Utils.toBase64Encode(res));
			encodedMessage.setIntialVector(Utils.toBase64Encode(salt));
			
			return encodedMessage;

		} catch (Exception e) {
			throw new Exception(e);
		}
	}
	
	
	public  EncodedMessage hashPassword(String cipher, final String password,  final int iterations,
			final int keyLength, byte[] salt) throws Exception {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(cipher);
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			
			EncodedMessage encodedMessage = new EncodedMessage();
			
			encodedMessage.setBase64Decoded( Utils.toBase64Encode(res));
			encodedMessage.setIntialVector(Utils.toBase64Encode(salt));
			
			return encodedMessage;

		} catch (Exception e) {
			throw new Exception(e);
		}
	}
	
	public static byte[] getNextSalt() {
	    byte[] salt = new byte[16];
	    new SecureRandom().nextBytes(salt);
	    return salt;
	  }
	
	public static void main(String[] args) {
		String[] str = { "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA1" };
		
		PBKDFDeriveKey  key  =  new PBKDFDeriveKey();
		
		for (int i = 0; i < str.length; i++) {
			
			String cipher =str [i];
			String msg = "8gWifi.org";
			int rounds = 10000;
			
			try {
				System.out.println(key.hashPassword(cipher, msg, rounds, 100+ i));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			
		}
	}

}
