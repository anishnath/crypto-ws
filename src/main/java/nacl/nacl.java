package nacl;

import org.abstractj.kalium.crypto.Advanced;
import org.abstractj.kalium.crypto.Random;

import cacerts.Utils;

public class nacl {
	
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
       
       String enc = nacl.encrypt(pwd, "a23c6e1a4aa987e766ecad497f2f4166fb4117b64adfb8bc".getBytes(), "thisismystrongpasswordof32bitkey".getBytes());
       System.out.println(enc);
       String dec = nacl.decrypt(enc, nonce, "thisismystrongpasswordof32bitkey".getBytes());
       
       System.out.println(dec);
        
	}

}
