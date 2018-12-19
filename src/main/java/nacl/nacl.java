package nacl;

import org.abstractj.kalium.crypto.Advanced;
import org.abstractj.kalium.crypto.Aead;
import org.abstractj.kalium.crypto.Random;

import cacerts.Utils;

public class nacl {
	
	
	public String aeadencrypt(String plaintext, String aad, byte[] nonce, byte[] key) throws Exception
	{
		try {
			Aead advanced = new Aead(key);
			byte[] ciphertext = advanced.encrypt(nonce,plaintext.getBytes(), aad.getBytes()); // encrypt
			return Utils.toHexEncoded(ciphertext);
		} catch (Exception e) {
			throw e;
		}
	}
	
	public String aeaddecrypt(String ciphertext,String aad, byte[] nonce, byte[] key)
	{
		byte[]ct = Utils.hexToBytes(ciphertext);
		Aead advanced = new Aead(key);
		byte [] plaintext = advanced.decrypt(nonce,ct, aad.getBytes()); // decrypt
		return new String(plaintext);
		
	}
	
	public String encrypt(String plaintext, byte[] nonce, byte[] key) throws Exception
	{
		try {
			Advanced advanced = new Advanced();
			byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext.getBytes(), nonce, key); // encrypt
			return Utils.toHexEncoded(ciphertext);
		} catch (Exception e) {
			throw e;
		}
	}
	
	public String decrypt(String ciphertext, byte[] nonce, byte[] key)
	{
		byte[]ct = Utils.hexToBytes(ciphertext);
		Advanced advanced = new Advanced();
		byte [] plaintext = advanced.crypto_stream_xsalsa20_xor(ct, nonce, key); // decrypt
		return new String(plaintext);
		
	}
	
	public static void main(String[] args) throws Exception {
		Random random = new Random();
        
        byte[] nonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        String pwd = "Hello 8gwifi.org";
        byte[] plaintext = pwd.getBytes();
        
        
        
        System.out.println(new String(plaintext));
        
       byte[] b =  Utils.getIV(24);
       
       String h = Utils.toHexEncoded(b);
       
       System.out.println(h);
       
       nacl nacl = new nacl();
       
       String enc = nacl.encrypt(pwd, nonce, "thisismystrongpasswordof32bitkey".getBytes());
       System.out.println(enc);
       String dec = nacl.decrypt(enc, nonce, "thisismystrongpasswordof32bitkey".getBytes());
       
       System.out.println(dec);
       
       
       for (int i = 1; i < 40; i++) {
    	   
    	   try {
    		   
    		   nonce = random.randomBytes(i);
			enc = nacl.aeadencrypt(pwd, "aead",nonce, "thisismystrongpasswordof32bitkey".getBytes());
			   System.out.println(enc + "i== " + i);
		} catch (Exception e) {
			 
		}
    	   
		
	}
       
      
       
        
	}

}
