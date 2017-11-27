package pgp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;

import cacerts.Utils;

/**
 * 
 * @author Anish Nath 
 * For Demo Visit https://8gwifi.org
 *
 */

public class PGPRSAKeyPairGenerator {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private int keysize = 2048;

	public PGPRSAKeyPairGenerator() {

	}

	public PGPRSAKeyPairGenerator(int p_keysize) {
		this.keysize = p_keysize;

	}

	private pgppojo exportKeyPair(PublicKey publicKey, PrivateKey privateKey, String identity, char[] passPhrase,
			final String algo) {

		pgppojo pgPpojo = new pgppojo();

		try {
			String path = System.getProperty("java.io.tmpdir");
			String fullPathSecretKey = path + "/" + UUID.randomUUID().toString();
			String fullPathPublicKey = path + "/" + UUID.randomUUID().toString();

			FileOutputStream out1 = new FileOutputStream(fullPathSecretKey);
			FileOutputStream out2 = new FileOutputStream(fullPathPublicKey);
			
			int PGPEncryptedData=1; //Defaulted to Idea

						
			if("IDEA".equals(algo))
			{
				PGPEncryptedData=1;
			}
			
			if("TRIPLE_DES".equals(algo))
			{
				PGPEncryptedData=2;
			}
			
			if("CAST5".equals(algo))
			{
				PGPEncryptedData=3;
			}
			
			if("BLOWFISH".equals(algo))
			{
				PGPEncryptedData=4;
			}
			if("SAFER".equals(algo))
			{
				PGPEncryptedData=5;
			}
			
			if("DES".equals(algo))
			{
				PGPEncryptedData=5;
			}
			
			if("AES_128".equals(algo))
			{
				PGPEncryptedData=7;
			}
			
			if("AES_192".equals(algo))
			{
				PGPEncryptedData=8;
			}
			
			if("AES_256".equals(algo))
			{
				PGPEncryptedData=9;
			}
			
			if("TWOFISH".equals(algo))
			{
				PGPEncryptedData=10;
			}


			PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, PGPPublicKey.RSA_GENERAL,
					publicKey, privateKey, new Date(), identity, PGPEncryptedData, passPhrase, null, null,
					new SecureRandom(), "BC");

			OutputStream secretOut = new ArmoredOutputStream(out1);

			secretKey.encode(secretOut);

			secretOut.close();

			OutputStream publicOut = new ArmoredOutputStream(out2);

			PGPPublicKey key = secretKey.getPublicKey();

			key.encode(publicOut);

			publicOut.close();

			pgPpojo.setPrivateKey(Utils.readFile(fullPathSecretKey, Charset.defaultCharset()));
			pgPpojo.setPubliceKey(Utils.readFile(fullPathPublicKey, Charset.defaultCharset()));

			// Silently Delete the temporary File Security DONOT Store any Thing
			// on
			// the servers
			try {
				File file = new File(fullPathSecretKey);
				file.delete();
			} catch (Exception ex) {
				// DO Nothing
			}

			// Silently Delete the temporary File Security
			try {
				File file = new File(fullPathPublicKey);
				file.delete();
			} catch (Exception ex) {
				// DO Nothing
			}

			return pgPpojo;
		} catch (Exception e) {
			pgPpojo.setErrorMessage(e.getMessage());
		}
		return pgPpojo;

	}

	public pgppojo genKeyPair(String identity, char[] passPhrase, final String algo) throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(this.keysize);
		KeyPair kp = kpg.generateKeyPair();
		return exportKeyPair(kp.getPublic(), kp.getPrivate(), identity, passPhrase, algo);

	}
	
	public static void main(String[] args) throws Exception {
		
		String identity = "anish";
		String passPhrase = "8gwifi.org";
		int keySize=1024;
		PGPRSAKeyPairGenerator generator  = new PGPRSAKeyPairGenerator(keySize);
		String algo = "BLOWFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "AES_256";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "AES_192";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "AES_128";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		
		keySize=2048;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "BLOWFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=4098;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "BLOWFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "CAST5";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=2048;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "CAST5";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=4098;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "CAST5";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TWOFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=2048;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TWOFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=4098;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TWOFISH";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=1024;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TRIPLE_DES";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=2048;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TRIPLE_DES";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		keySize=4098;
		generator  = new PGPRSAKeyPairGenerator(keySize);
		algo = "TRIPLE_DES";
		System.out.println(generator.genKeyPair(identity, passPhrase.toCharArray(), algo));
		
		
		
		
		
	}
}