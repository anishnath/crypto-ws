import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

public class elgamal {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String[] args) throws Exception {


	    byte[] input = "ANISHNATHNATH".getBytes();
	    Cipher cipher = Cipher.getInstance("ElGamal", "BC");
	    KeyPair pair = Utils.generateRSAKeyPair("ElGamal", 160);
	    Key pubKey = pair.getPublic();
	    Key privKey = pair.getPrivate();
	    
	    //System.out.println(Utils.toPem(pair));
	    
	    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	    byte[] cipherText = cipher.doFinal(input);
	    System.out.println("cipher: " + new String(cipherText));

	    cipher.init(Cipher.DECRYPT_MODE, privKey);
	    byte[] plainText = cipher.doFinal(cipherText);
	    System.out.println("plain : " + new String(plainText));
	  }

}
