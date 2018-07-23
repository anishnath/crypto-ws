package elgamal;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;
import pem.PemParser;
import pojo.elgamlpojo;

/**
 * 
 * @author aninath
 * Demo @ https://8gwifi.org
 *
 */
public class elgamal {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public elgamlpojo generateKeys() throws Exception {
		return generateKeys(160);
	}

	public elgamlpojo generateKeys(int keysize) throws Exception {
		KeyPair pair = Utils.generateRSAKeyPair("ELGAMAL", keysize);

		Key privKey = pair.getPrivate();

		String s = Utils.toBase64Encode(privKey.getEncoded());

		StringBuilder builder = new StringBuilder();
		builder.append("-----BEGIN PRIVATE KEY-----");
		builder.append("\n");
		builder.append(s);
		builder.append("\n");
		builder.append("-----END PRIVATE KEY-----");

		String pKey = Utils.toPem(pair.getPublic());

		elgamlpojo elgamlpojo = new elgamlpojo();
		elgamlpojo.setKeySize(keysize);
		elgamlpojo.setPublicKey(pKey);
		elgamlpojo.setPrivateKey(builder.toString());

		return elgamlpojo;

	}

	public String decrypt(String msg, String algo, String key) throws Exception {

		Cipher cipher = Cipher.getInstance(algo, "BC");

		PemParser parser = new PemParser();
		Object obj = parser.parsePemFileObject(key);

		PublicKey publickey = null;
		PrivateKey privatekey = null;

		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			publickey = (PublicKey) obj;

		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey) {
			publickey = (org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey) obj;
		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey) {
			privatekey = (org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey) obj;
		}

		if (publickey != null) {
			throw new Exception(
					"ElGamalPrivateKeys are required for decryption Supplied Parameter is ElGamal Public Key");
		}

		if (null == privatekey) {
			throw new Exception("ElGamalPrivateKeys are required for decryption ");
		}

		cipher.init(Cipher.DECRYPT_MODE, privatekey);

		byte[] b = Utils.decodeBASE64(msg);

		byte[] plainText = cipher.doFinal(b);

		return new String(plainText);

	}

	public String encrypt(String msg, String algo, String key) throws Exception {

		Cipher cipher = Cipher.getInstance(algo, "BC");

		PemParser parser = new PemParser();
		Object obj = parser.parsePemFileObject(key);
		
		//System.out.println(obj.getClass());

		PublicKey publickey = null;
		PrivateKey privatekey = null;

		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			publickey = (PublicKey) obj;

		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey) {
			publickey = (org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey) obj;
		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey) {
			privatekey = (org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey) obj;
		}

		if (privatekey != null) {
			throw new Exception(
					"ElGamalPublicKeyParameters are required for encryption Supplied Parameter is ElGamal Private Key");
		}

		if (null == publickey) {
			throw new Exception("ElGamalPublicKeyParameters are required for encryption");
		}

		if (publickey != null) {
			cipher.init(Cipher.ENCRYPT_MODE, publickey);
		}

		byte[] cipherText = cipher.doFinal(msg.getBytes("UTF-8"));

		return Utils.toBase64Encode(cipherText);

	}

	public static void main(String[] args) throws Exception {
		
//		for (int i = 0; i < 100000; i++) {
//			try {
//				//KeyPair pair = Utils.generateRSAKeyPair("ELGAMAL", i);
//				System.out.println(i);
//			} catch (Exception e) {
//				
//			}
//		}

		byte[] input = "ANISHNATHANISHNATHA".getBytes();
		Cipher cipher = Cipher.getInstance("ELGAMAL", "BC");
		KeyPair pair = Utils.generateRSAKeyPair("ELGAMAL", 512);
		Key pubKey = pair.getPublic();
		Key privKey = pair.getPrivate();

		String s = Utils.toBase64Encode(privKey.getEncoded());

		StringBuilder builder = new StringBuilder();
		builder.append("-----BEGIN PRIVATE KEY-----");
		builder.append("\n");
		builder.append(s);
		builder.append("\n");
		builder.append("-----END PRIVATE KEY-----");

		System.out.println(builder.toString());

		PemParser parser = new PemParser();

		parser.parsePemFile(builder.toString());

		String pKey = Utils.toPem(pair.getPublic());
		System.out.println(pKey);
		System.out.println(parser.parsePemFileObject(pKey));

		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(cipherText));

		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(cipherText);
		System.out.println("plain : " + new String(plainText));

		String encrypted = new elgamal().encrypt("ANISHNATHANISHNATHA", "ELGAMAL", pKey);

		System.out.println(encrypted);

		String pla = new elgamal().decrypt(encrypted, "ELGAMAL", builder.toString());

		System.out.println(pla);

	}

}
