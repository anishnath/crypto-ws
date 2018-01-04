package cipher;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;
import pbe.PBEEncryptDecrypt;


/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

public class EncryptDecrypt {

	public static final int ROUNDS = 40000;
	public static final String FIXED_SALT = "FIXED_SA";
	public static int AES_KEY_SIZE = 128; // in bits
	public static final int GCM_NONCE_LENGTH = 12; // in bytes
	public static final int GCM_TAG_LENGTH = 16; // in bytes
	private static final byte[] FIXED_IV_24 =new byte[24]; 
	private static final byte[] FIXED_IV_20 =new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private static final byte[] FIXED_IV_16 =new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private static final byte[] FIXED_IV_12 =new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private static final byte[] FIXED_IV_8 =new byte[]  { 0, 0, 0, 0, 0, 0, 0, 0 };

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	// Convert cipherparameter in Upper Case..
	public String encrypt(String plaintext, String secretkey, String cipherparameter) throws Exception {

		if (null == cipherparameter || cipherparameter.trim().length() == 0) {
			throw new Exception("Cipher Paramater is Null or Empty");
		}

		if (null == secretkey || secretkey.trim().length() == 0) {
			throw new Exception("Secret key is Null or Empty");
		}

		cipherparameter = cipherparameter.trim().toUpperCase();
		System.out.println("cipherparameter "+ cipherparameter);
		try {
		if (cipherparameter != null && (cipherparameter.startsWith("AES_") && !cipherparameter.contains("GCM"))) {
		
				byte[] ivBytes = null;
				SecureRandom random = new SecureRandom();
				byte bytes[] = new byte[20];
				random.nextBytes(bytes);
				byte[] saltBytes = bytes;
				// Derive the key
				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

				int keySize = 128;
				if (cipherparameter.startsWith("AES_192")) {
					keySize = 192;
				}
				if (cipherparameter.startsWith("AES_256")) {
					keySize = 256;
				}

				PBEKeySpec spec = new PBEKeySpec(secretkey.toCharArray(), saltBytes, ROUNDS, keySize);

				SecretKey secretKey1 = factory.generateSecret(spec);
				SecretKeySpec secret = new SecretKeySpec(secretKey1.getEncoded(), "AES");
				// encrypting the word
				Cipher cipher = Cipher.getInstance(cipherparameter);
				cipher.init(Cipher.ENCRYPT_MODE, secret);

				byte[] buffer = null;

				byte[] encryptedTextBytes = null;

				encryptedTextBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
				if (!cipherparameter.contains("ECB")) {
					AlgorithmParameters params = cipher.getParameters();
					ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
					buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
					System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
					System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
					System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length,
							encryptedTextBytes.length);

				} else {
					buffer = new byte[saltBytes.length + encryptedTextBytes.length];
					System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
					System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length, encryptedTextBytes.length);

				}

				return Utils.toBase64Encode(buffer);

			
		}

		if (cipherparameter != null && (cipherparameter.startsWith("PBE")
				|| (cipherparameter.contains("OLDPBEWITHSHAANDTWOFISH")
				|| (cipherparameter.contains("OLDPBEWITHSHAAND3")
				))) 
				){
			return PBEEncryptDecrypt.encrypt(plaintext, secretkey, cipherparameter, ROUNDS, FIXED_SALT);

		}
		
		if (cipherparameter != null && (cipherparameter.contains("THREE"))) {
			return ThreeFish.encrypt(plaintext, secretkey, cipherparameter);

		}

		if (cipherparameter != null && (cipherparameter.contains("GCM")
				|| (cipherparameter.contains("CAST5") 
			    || (cipherparameter.contains("XSALSA20")
				|| (cipherparameter.contains("SALSA20") 
				|| cipherparameter.contains("CHACHA")
				|| cipherparameter.contains("DSTU7624") 
				|| cipherparameter.contains("TEA")
				|| cipherparameter.contains("HC128")
				|| cipherparameter.contains("HC256")
				|| cipherparameter.contains("GRAINV1")
				|| cipherparameter.contains("GRAIN128")
				|| cipherparameter.contains("GOST28147")
				|| cipherparameter.contains("SM4") 
				|| cipherparameter.contains("XTEA")))))) {
		
				AES_KEY_SIZE = 128;
				if (cipherparameter.startsWith("AES_192")) {
					AES_KEY_SIZE = 192;
				}
				if (cipherparameter.startsWith("AES_256")
						|| cipherparameter.contains("CHACHA")
						|| cipherparameter.contains("GRAIN128")
						|| cipherparameter.contains("GOST28147")
						|| cipherparameter.contains("XSALSA20")) {
					AES_KEY_SIZE = 256;
				}

				String alg = "AES";

				String plaintextKey = Utils.generateKey(alg, AES_KEY_SIZE, secretkey);
				SecretKeySpec sks = new SecretKeySpec(Utils.decodeBASE64(plaintextKey), alg);
				Cipher cipher = Cipher.getInstance(cipherparameter);
				byte[] input = plaintext.getBytes("UTF-8");
				byte[] tkb = secretkey.getBytes("UTF-8");

				byte[] iv = new byte[tkb.length];
				System.arraycopy(tkb, 0, iv, 0, tkb.length);
				if (cipherparameter.contains("GCM")) {
					cipher.init(Cipher.ENCRYPT_MODE, sks, new GCMParameterSpec(128, iv));
					cipher.updateAAD(tkb);
				}
				else if (cipherparameter.startsWith("CHACHA")
						|| cipherparameter.contains("GRAINV1")
						|| cipherparameter.contains("HC128")
						|| cipherparameter.contains("SALSA20")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_8);
					cipher.init(Cipher.ENCRYPT_MODE, sks, ivspec);
					
				}
				else if (
						cipherparameter.contains("CHACHA7539")
						|| cipherparameter.contains("GRAIN128")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_12);
					cipher.init(Cipher.ENCRYPT_MODE, sks, ivspec);
				}
				else if (
						cipherparameter.contains("HC256")
						
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_16);
					cipher.init(Cipher.ENCRYPT_MODE, sks, ivspec);
					
				}
				else if ( cipherparameter.contains("XSALSA20")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_24);
					cipher.init(Cipher.ENCRYPT_MODE, sks, ivspec);
					
				}
				else {
					cipher.init(Cipher.ENCRYPT_MODE, sks);
				}

				byte[] opbytes = new byte[cipher.getOutputSize(plaintext.length())];

				// Perform crypto
				int ctlen = cipher.update(input, 0, input.length, opbytes);
				ctlen += cipher.doFinal(opbytes, ctlen);
				byte[] output = new byte[ctlen];
				System.arraycopy(opbytes, 0, output, 0, ctlen);
				return Utils.toBase64Encode(output);

			

		}

		// if (cipherparameter != null &&
		// ("Blowfish".equalsIgnoreCase(cipherparameter.trim())
		// || "Twofish".equalsIgnoreCase(cipherparameter.trim())
		// || "CAST5".equalsIgnoreCase(cipherparameter.trim())
		// || "IDEA".equalsIgnoreCase(cipherparameter.trim())
		// || "DESede".equalsIgnoreCase(cipherparameter.trim())
		// || "AES".equalsIgnoreCase(cipherparameter.trim())
		// || "DESede".equalsIgnoreCase(cipherparameter.trim())
		// || "DESede/CBC/PKCS5Padding".equalsIgnoreCase(cipherparameter)
		// || "DES/CBC/NoPadding".equalsIgnoreCase(cipherparameter)
		// || "DES/CBC/PKCS5Padding".equalsIgnoreCase(cipherparameter)
		// || "RIJNDAEL".equalsIgnoreCase(cipherparameter)
		// || "DESede/CBC/NoPadding".equalsIgnoreCase(cipherparameter))) {

		

		byte[] iv;

		if (cipherparameter.contains("AES/CBC")  ) {
			// The INitialVector Must Be 16 bit
			iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		} else{
			iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
		}

		IvParameterSpec ivspec = new IvParameterSpec(iv);
		byte[] keyData = (secretkey).getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, cipherparameter.trim());
		Cipher cipher = Cipher.getInstance(cipherparameter);
		if (cipherparameter.contains("AES/CBC")) {
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);
		} else {
			if (cipherparameter.equalsIgnoreCase("DES") 
					||  cipherparameter.startsWith("DES/ECB/")) {
				DESKeySpec keySpec = new DESKeySpec(secretkey.getBytes());
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				SecretKey key = factory.generateSecret(keySpec);
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			else if (cipherparameter.contains("DES/CBC/"))
			{
				DESKeySpec keySpec = new DESKeySpec(secretkey.getBytes());
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				SecretKey key1 = factory.generateSecret(keySpec);
			    // initialize the cipher with the key and IV
			    cipher.init(Cipher.ENCRYPT_MODE, key1, ivspec);
				
			}
			//ECB mode cannot use IV
			else if (cipherparameter.contains("ECB")) {
				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			}
			else {
				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);
			}

		}

		byte[] hasil = cipher.doFinal(plaintext.getBytes());
		String s = Utils.toBase64Encode(hasil);
		return s;
		} catch( Exception ex )
		{
			throw new Exception(ex);
		}

	}

	// Convert Cipher Parameter in Upper case..
	public String decrypt(String base64text, String secretkey, String cipherparameter) throws Exception {
		if (null == cipherparameter || cipherparameter.trim().length() == 0) {
			throw new Exception("Cipher Paramater is Null or Empty");
		}

		if (null == secretkey || secretkey.trim().length() == 0) {
			throw new Exception("Secret key is Null or Empty");
		}

		cipherparameter = cipherparameter.trim().toUpperCase();
		System.out.println("cipherparameter "+ cipherparameter);

		try {

		if (cipherparameter != null && (cipherparameter.startsWith("AES_") && !cipherparameter.contains("GCM"))) {
			
				Cipher cipher = Cipher.getInstance(cipherparameter);
				ByteBuffer buffer = ByteBuffer.wrap(new Base64().decode(base64text));
				byte[] saltBytes = new byte[20];
				buffer.get(saltBytes, 0, saltBytes.length);
				byte[] encryptedTextBytes = null;
				byte[] ivBytes1 = null;

				if (!cipherparameter.contains("ECB")) {
					ivBytes1 = new byte[cipher.getBlockSize()];
					buffer.get(ivBytes1, 0, ivBytes1.length);
					encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes1.length];
				} else {
					encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length];
				}

				buffer.get(encryptedTextBytes);

				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				int keySize = 128;
				if (cipherparameter.startsWith("AES_192")) {
					keySize = 192;
				}
				if (cipherparameter.startsWith("AES_256")) {
					keySize = 256;
				}

				PBEKeySpec spec = new PBEKeySpec(secretkey.toCharArray(), saltBytes, ROUNDS, keySize);
				SecretKey secretKey1 = factory.generateSecret(spec);
				SecretKeySpec secret = new SecretKeySpec(secretKey1.getEncoded(), "AES");

				if (!cipherparameter.contains("ECB")) {
					cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes1));
				} else {
					cipher.init(Cipher.DECRYPT_MODE, secret);
				}

				byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
				return new String(decryptedTextBytes);

			
		}

		if (cipherparameter != null && (cipherparameter.contains("GCM")
				|| (cipherparameter.contains("CAST5") 
					    || (cipherparameter.contains("XSALSA20")
						|| (cipherparameter.contains("SALSA20") 
						|| cipherparameter.contains("CHACHA")
						|| cipherparameter.contains("DSTU7624") 
						|| cipherparameter.contains("TEA")
						|| cipherparameter.contains("HC128")
						|| cipherparameter.contains("HC256")
						|| cipherparameter.contains("GRAINV1")
						|| cipherparameter.contains("GRAIN128")
						|| cipherparameter.contains("GOST28147")
						|| cipherparameter.contains("SM4") 
						|| cipherparameter.contains("XTEA"))))))
		{
			

				AES_KEY_SIZE = 128;
				if (cipherparameter.startsWith("AES_192")) {
					AES_KEY_SIZE = 192;
				}
				
				if (cipherparameter.startsWith("AES_256")
						|| cipherparameter.contains("CHACHA")
						|| cipherparameter.contains("GRAIN128")
						|| cipherparameter.contains("GOST28147")
						|| cipherparameter.contains("XSALSA20")) {
					AES_KEY_SIZE = 256;
				}

				String alg = "AES";

				String plaintextKey = Utils.generateKey(alg, AES_KEY_SIZE, secretkey);
				SecretKeySpec sks = new SecretKeySpec(Utils.decodeBASE64(plaintextKey), alg);
				Cipher cipher = Cipher.getInstance(cipherparameter);

				// Setup byte arrays
				byte[] input = Utils.decodeBASE64(base64text);
				byte[] tkb = secretkey.getBytes("UTF-8");
				byte[] iv = new byte[tkb.length];
				System.arraycopy(tkb, 0, iv, 0, tkb.length);
				if (cipherparameter.contains("GCM")) {
				cipher.init(Cipher.DECRYPT_MODE, sks, new GCMParameterSpec(128, iv));
				cipher.updateAAD(tkb);
				}
				else if (cipherparameter.startsWith("CHACHA")
						|| cipherparameter.contains("GRAINV1")
						|| cipherparameter.contains("HC128")
						|| cipherparameter.contains("SALSA20")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_8);
					cipher.init(Cipher.DECRYPT_MODE, sks, ivspec);
					
				}
				else if (
						cipherparameter.contains("CHACHA7539")
						|| cipherparameter.contains("GRAIN128")

						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_12);
					cipher.init(Cipher.DECRYPT_MODE, sks, ivspec);
				}
				else if (
						cipherparameter.contains("HC256")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_16);
					cipher.init(Cipher.DECRYPT_MODE, sks, ivspec);
					
				}
				else if ( cipherparameter.contains("XSALSA20")
						)
				{
					IvParameterSpec ivspec = new IvParameterSpec(FIXED_IV_24);
					cipher.init(Cipher.DECRYPT_MODE, sks, ivspec);
					
				}
				else {
					cipher.init(Cipher.DECRYPT_MODE, sks);
				}
				byte[] opbytes = new byte[cipher.getOutputSize(input.length)];

				// Perform crypto
				int ctlen = cipher.update(input, 0, input.length, opbytes);
				ctlen += cipher.doFinal(opbytes, ctlen);
				byte[] output = new byte[ctlen];
				System.arraycopy(opbytes, 0, output, 0, ctlen);
				return new String(output, "UTF-8");

			} 
		

		if (cipherparameter != null && (cipherparameter.startsWith("PBE")
				|| (cipherparameter.contains("OLDPBEWITHSHAANDTWOFISH")
				|| (cipherparameter.contains("OLDPBEWITHSHAAND3")
				))) 
				){
			return PBEEncryptDecrypt.decrypt(base64text, secretkey, cipherparameter, ROUNDS, FIXED_SALT);

		}
		
		if (cipherparameter != null && (cipherparameter.contains("THREE"))) {
			return ThreeFish.decrypt(base64text, secretkey, cipherparameter);

		}
		
		byte[] iv;

		if (cipherparameter.contains("AES/CBC")  ) {
			// The INitialVector Must Be 16 bit
			iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		} else{
			iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
		}

		IvParameterSpec ivspec = new IvParameterSpec(iv);
		byte[] keyData = (secretkey).getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, cipherparameter.trim());
		Cipher cipher = Cipher.getInstance(cipherparameter);
		if (cipherparameter.contains("AES/CBC")) {
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
		} else {
			if (cipherparameter.equalsIgnoreCase("DES") 
					|| cipherparameter.startsWith("DES/ECB/")) {
				DESKeySpec keySpec = new DESKeySpec(secretkey.getBytes());
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				SecretKey key = factory.generateSecret(keySpec);
				cipher.init(Cipher.DECRYPT_MODE, key);
			} 
			
			else if (cipherparameter.contains("DES/CBC/"))
			{
				DESKeySpec keySpec = new DESKeySpec(secretkey.getBytes());
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				SecretKey key1 = factory.generateSecret(keySpec);
			    // initialize the cipher with the key and IV
			    cipher.init(Cipher.DECRYPT_MODE, key1, ivspec);
				
			}
			//ECB mode cannot use IV
			else if (cipherparameter.contains("ECB")) {
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			}
			else {
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
			}

		}

		byte[] hasil = cipher.doFinal(Utils.decodeBASE64(base64text));
		
		return new String(hasil);
		
		
	}catch (Exception ex) {
			
			throw new Exception(ex);
		}
	}

	public static void main(String[] args) throws Exception {
		
		byte[] iv  = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		String password = "Hello";
		String secretkey = "My Name is Anish";
		String plaintext = "Hello Anish NATH";
		String cipherparameter = "DES/CBC/PKCS5Padding";
		
//		DESKeySpec keySpec = new DESKeySpec(secretkey.getBytes());
//		SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
//		
//		SecretKey key1 = factory.generateSecret(keySpec);
//		
//		
//		//KeyGenerator kg = KeyGenerator.getInstance("DES");
//	    Cipher c = Cipher.getInstance(cipherparameter);
//	    //Key key1 = kg.generateKey();
//
//	    c.init(Cipher.ENCRYPT_MODE, key1,ivspec);
//	    byte input[] = "Hello Anish".getBytes();
//	    byte encrypted[] = c.doFinal(input);
//	    //byte iv[] = c.getIV();
//	    
//	    System.out.println(Utils.toBase64Encode(encrypted));
//	    
//	   // key = kg.generateKey();
//	    IvParameterSpec dps = new IvParameterSpec(iv);
//	    c.init(Cipher.DECRYPT_MODE, key1, dps);
//	    byte output[] = c.doFinal(encrypted);
//	    System.out.println(new String(output));
//	    
//	    System.exit(1);

		EncryptDecrypt decrypt = new EncryptDecrypt();

		Set<String> str = new TreeSet<String>();
		for (Provider provider : Security.getProviders()) {
			// System.out.println(provider.getName());
			for (String key : provider.stringPropertyNames()) {
				// System.out.println("\t X-" + key + "\t Y-" +
				// provider.getProperty(key));

				if (key.contains("Cipher") && !key.startsWith("Alg")) {
					if (key.startsWith("Cipher.")) {
						cipherparameter = key.substring("Cipher.".length(), key.length());
						if (!cipherparameter.startsWith("DSTU7624-128KW") && !cipherparameter.startsWith("CCM")
								&& !cipherparameter.startsWith("ARC4") 
								&& !cipherparameter.startsWith("DSTU7624-256KW")
								&& !cipherparameter.contains("OLDPBEWITH")
								&& !cipherparameter.contains("CHACHA7539")
								&& !cipherparameter.contains("ChaCha7539")
								&& !cipherparameter.contains("XSalsa")
								&& !cipherparameter.contains("XSALSA20")
								&& !cipherparameter.contains("IES")
								&& !cipherparameter.contains("ElGamal")
								&& !cipherparameter.contains("ELGAMAL")
								&& !cipherparameter.contains("ELGAMAL/PKCS1")
								&& !cipherparameter.contains("RC5-64")
								&& !cipherparameter.startsWith("DSTU7624-512KW")
								&& !cipherparameter.startsWith("DSTU7624")
								&& !cipherparameter.startsWith("BROKEN") && !cipherparameter.startsWith("RSA")
								&& !cipherparameter.startsWith("ARCFOUR") && !cipherparameter.startsWith("1")
								&& !cipherparameter.startsWith("OID") && !cipherparameter.startsWith("2")
								&& !cipherparameter.contains(" ") && !cipherparameter.contains("WRAP")
								&& !cipherparameter.contains("Wrap")) {
							str.add(cipherparameter);
						}
					}
					// System.out.println("XX");
					// System.out.println("\t X-" + key + "\t Y-" +
					// provider.getProperty(key));
					if (key.startsWith("Cipher.AES") || key.startsWith("Cipher.DES") || key.startsWith("Cipher.RIJ")) {
						 cipherparameter = key.substring("Cipher.".length(), key.length());
						// System.out.println(cipherparameter);

					}

				}
			}
		}
		
		System.out.println("HashSet " + str.size());
		
		

		for (Iterator iterator = str.iterator(); iterator.hasNext();) {
			try {
				 cipherparameter = (String) iterator.next();
				

				
				// System.out.println(plaintext.length());
				String s = decrypt.encrypt(plaintext, secretkey, cipherparameter);

				if (s != null) {

					//System.out.println(cipherparameter + "\t " + s);
					String dec = decrypt.decrypt(s,secretkey,cipherparameter);
					if(dec!=null)
					{
						System.out.println("Cipher Paramter " + cipherparameter + "\t " + dec.equals(plaintext));
					}

				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		
		String[] cipherparameter1={"AES/CBC/PKCS5Padding","AES/CBC/NoPadding",
				"AES/ECB/NoPadding",
				"DES/CBC/NoPadding",
				"DES/CBC/NoPadding",
				"DES/CBC/PKCS5Padding",
				"DES/ECB/NoPadding",
				"DES/ECB/PKCS5Padding",
				"DESede/CBC/NoPadding",
				"DESede/CBC/PKCS5Padding",
				"DESede/ECB/NoPadding",
				"DESede/ECB/PKCS5Padding",
				"AES/ECB/PKCS5Padding"};
		
			for (int i = 0; i < cipherparameter1.length; i++) {
				str.add(cipherparameter1[i]);
				try {
				// System.out.println(plaintext.length());
				String s = decrypt.encrypt(plaintext, secretkey, cipherparameter1[i]);

				if (s != null) {

					//System.out.println(cipherparameter + "\t " + s);
					String dec = decrypt.decrypt(s,secretkey,cipherparameter1[i]);
					if(dec!=null)
					{
						
						//System.out.println("Cipher Paramter " + cipherparameter1[i] + "\t " +  "decrypted \t " + dec +"\t Equals " + dec.equals(plaintext));
					}

				}
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
			}
			
			System.out.println("HashSet " + str.size());
			
			for (Iterator iterator = str.iterator(); iterator.hasNext();) {
				//System.out.print(("\""+(String) iterator.next() + "\",").toUpperCase());
				System.out.println(((String) iterator.next() ).toUpperCase());
			}		

	}

}
