package cipher;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;
import pojo.EncodedMessage;

/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

public class MessageDigestCalc {

	public EncodedMessage calculateMessageDigest(String algo, final String message) throws Exception {
		if (null == algo || algo.trim().length() == 0) {
			throw new Exception("Message Digest Algo is Null or Empty");
		}

		if (null == message || message.trim().length() == 0) {
			throw new Exception("Message is Null or Empty");
		}

		EncodedMessage encodedMessage = new EncodedMessage();
		try {

			MessageDigest md = MessageDigest.getInstance(algo);
			md.update(message.getBytes());
			byte[] mdbytes = md.digest();
			encodedMessage.setMessage("Digest Length " + md.getDigestLength());
			encodedMessage.setBase64Encoded(Utils.toBase64Encode(mdbytes));
			encodedMessage.setHexEncoded(Utils.toHexEncoded(mdbytes));
		} catch (Exception e) {
			throw new Exception(e);
		}

		return encodedMessage;

	}
	
	public static byte[] calculateMessageDigest(String algo, final byte[] message) throws Exception {
		
		if (null == algo || algo.trim().length() == 0) {
			throw new Exception("Message Digest Algo is Null or Empty");
		}
		
		byte[] mdbytes=null;
		try {

			MessageDigest md = MessageDigest.getInstance(algo);
			md.update(message);
			mdbytes = md.digest();
			
		} catch (Exception e) {
			throw new Exception(e);
		}

		return mdbytes;

	}

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		
		MessageDigestCalc messageDigestCalc =  new MessageDigestCalc();
		
		Set<String> set1 =  new TreeSet<String>();

		for (Provider provider : Security.getProviders()) {
			// System.out.println(provider.getName());
			for (String key : provider.stringPropertyNames()) {

				if (key.startsWith("MessageDigest.")) {
					String cipherparameter = key.substring("MessageDigest.".length(), key.length());
					
					if(!cipherparameter.contains("ImplementedIn"))
					{
					
					try {
						//System.out.println(cipherparameter);
						String message = "Anish";
						EncodedMessage encodedMessage = messageDigestCalc.calculateMessageDigest(cipherparameter, message);
						System.out.println(encodedMessage);
						//System.out.println(cipherparameter);
						set1.add(cipherparameter);
					} catch (Exception e) {
						//System.out.println("Exception " + cipherparameter);
						
					}
				}
				}

			}
		}
		
		System.out.println("Sizee-->" + set1.size());
		
		for (Iterator iterator = set1.iterator(); iterator.hasNext();) {
			String string = (String) iterator.next();
			
			
			
			System.out.print(("\""+(String) string+ "\",").toLowerCase());
			
		}

	}
}
