package mac;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Hmac {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public byte[] calculateHMAC(final String msg, final String key, final String algo) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), algo);
			Mac mac = Mac.getInstance(algo);
			mac.init(signingKey);
			byte[] b = mac.doFinal(msg.getBytes());
			return b;
		} catch (Exception e) {
			System.out.println("Error -- " +algo);
			return ("Algo " + algo + " " +e.getMessage()).getBytes();
		} 

	}

	public static void main(String[] args) {
		String algo = "HmacSHA256";
		String msg = "anish";
		String key = "8gwifi.org";
		Hmac hmac = new Hmac();
		//System.out.println(hmac.calculateHMAC(msg, key, algo));

		algo = "PBEWithHmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));

		algo = "SslMacMD5";

		//System.out.println(hmac.calculateHMAC(msg, key, algo));

		algo = "HmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));

		algo = "PBEWithHmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SslMacMD5";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA256";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA256";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SslMacMD5";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA256";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA224";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA224";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SslMacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA224";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacPBESHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacMD5";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacPBESHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SslMacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA256";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacMD5";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWithHmacSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA224";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HmacSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		
		algo = "HMACRIPEMD128";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWITHHMACSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACSHA1";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACSHA256";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWITHHMACSHA";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACSHA224";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "DESEDEMAC64WITHISO7816-4PADDING";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "OLDHMACSHA512";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "DESWITHISO9797";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "RC5MAC/CFB8";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "OLDHMACSHA384";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "RC2MAC/CFB8";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACMD5";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACMD4";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACMD2";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "RC5MAC";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACTIGER";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SKIPJACKMAC/CFB8";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "PBEWITHHMACRIPEMD160";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "SKIPJACKMAC";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "IDEAMAC/CFB8";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "IDEAMAC";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "RC2MAC";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo = "HMACRIPEMD160";
		//System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="DES";
		System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="DESEDEMAC";
		System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="DESEDEMAC/CFB8";
		System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="SKIPJACKMAC";
		System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="SKIPJACKMAC/CFB8";
		System.out.println(hmac.calculateHMAC(msg, key, algo));
		algo="HMACTIGER";
		System.out.println(hmac.calculateHMAC(msg, key, algo));

		
	}

}
