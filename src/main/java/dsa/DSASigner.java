package dsa;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import cacerts.Utils;
import pgp.pgppojo;

/**
 * 
 * @author Anish Nath
 * Demo @  https://8gwifi.org
 *
 */
public class DSASigner {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public pgppojo generateKey(int keysize) throws Exception {
		pgppojo pgppojo = new pgppojo();
		KeyPair kp = Utils.generateRSAKeyPair("DSA", keysize);
		pgppojo.setPrivateKey(Utils.toPem(kp));
		pgppojo.setPubliceKey(Utils.toPem(kp.getPublic()));
		return pgppojo;

	}
	
	


	/**
	 * 
	 * @param inputfile
	 * @param signaturefile
	 * @param key
	 * @param signaturealgo
	 * @return
	 * @throws Exception
	 */
	public boolean verifysign(byte[] inputfile, byte[] signaturefile, String key, String signaturealgo)
			throws Exception {

		boolean verified = false;
		try {
			byte[] content = key.trim().getBytes();

			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);

			PEMParser parser = new PEMParser(br);

			PublicKey publickey = null;

			Object obj = parser.readObject();

			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
			}

			if (publickey == null) {
				throw new Exception(
						"DSA Public Key is not Valid, Please supply a Valid public key file to verify Signature ");
			}

			Signature sig = Signature.getInstance(signaturealgo, "BC");

			sig.initVerify(publickey);

			sig.update(inputfile);

			verified = sig.verify(signaturefile);

			return verified;

		} catch (Exception e) {
			throw new Exception(e);
		}

	}

	/**
	 * 
	 * @param b
	 * @param data
	 * @param signaturealgo
	 * @throws Exception
	 */
	public byte[] sign(byte[] b, String key, String signaturealgo) throws Exception {
		return sign(b, key, signaturealgo, null);
	}

	/**
	 * 
	 * @param b
	 *            Input Stream of the File
	 * @param data
	 *            The DSA Pem FIle
	 * @param password
	 *            Password of the Enctypted PEM file
	 * @return
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public byte[] sign(byte[] b, String key, String signaturealgo, String password) throws Exception {

		try {
			byte[] content = key.trim().getBytes();

			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);

			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();

			PrivateKey privateKey = null;
			PublicKey publickey = null;

			if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			}

			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
			}

			if (privateKey == null) {
				throw new Exception("Cannot formed DSA Private Key from the Supplied DSA Key DSA Key Invalid  ");
			}

			Signature dsa = Signature.getInstance(signaturealgo, "BC");

			dsa.initSign(privateKey);

			dsa.update(b);

			byte[] realSig = dsa.sign();

			return realSig;
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static void main(String[] args) throws Exception {

		/**
		 * Author Anish Demo @ 8gwifi.org
		 */
		DSASigner dsaPublicPrivateKeys = new DSASigner();
		// System.out.println(dsaPublicPrivateKeys.generateKey(1024));
		// System.out.println(dsaPublicPrivateKeys.generateKey(2048));
		// System.out.println(dsaPublicPrivateKeys.generateKey(4096));
		pgppojo pgppojo = dsaPublicPrivateKeys.generateKey(1024);

		System.out.println(pgppojo.getPrivateKey());
		System.out.println(pgppojo.getPubliceKey());

		String[] arr = { "SHA256withDSA", "NONEwithDSA", "SHA224withDSA", "SHA1withDSA" };

		byte[] b = "Anish".getBytes();

		String privateKey = "-----BEGIN DSA PRIVATE KEY-----\n"
				+ "MIIBugIBAAKBgQCyr14WVg6S4Bgj730FAFw6b9jQQXOpbT9hCoFsO3nRdeJbt7FZ\n"
				+ "74ZfteJvgcFKYh928x14FSNDGVPt8f/WYNvR54+zCsfGJDg1E8LUOTIxT424hW43\n"
				+ "mc+hYIdU/cptgzrt5w/GvCmUkryyZVwiihlJiZUjFcBb+wr6/v/GzDQLQQIVAN/Y\n"
				+ "mHITWd24BxLbBPi4t5UMOqNVAoGAXXJXWWaWfUmksn88ulC8My3ZC+OZWMDKoEbs\n"
				+ "DW0SbTBSK9wlrHWDWVMqFIFkDPA1TSJXm1Ll0PfxTOVTSHmWLzXU4Zivy5XX+ykP\n"
				+ "flf5S5Ylgt3PLCNMChyO2EdbZZwKNaZZbkzYzVX7uYPauDvz0JjwCOr31sVztbiq\n"
				+ "K4fHAzQCgYBEknoqONBTiG+l3jbDhDIQfntaCCQb+SY6QeQCQtFCCNL70blTz6dk\n"
				+ "dFtJ2g6RKNlmBX3l3tZwR7lxuPUpI3WZveuGVzvWuxbbUtmBbWbMYSV9BWbeKJKu\n"
				+ "aOySpITmsSGZzk7n2y2+nzk7exNdN9JiTGLUGyq1Ow2tfhD1WSbsDQIUSAtob3a+\n" + "6zP+LdRew0AHmbPi5jM=\n"
				+ "-----END DSA PRIVATE KEY-----";

		String publicKey = "-----BEGIN PUBLIC KEY-----\n"
				+ "MIIBtjCCASsGByqGSM44BAEwggEeAoGBALKvXhZWDpLgGCPvfQUAXDpv2NBBc6lt\n"
				+ "P2EKgWw7edF14lu3sVnvhl+14m+BwUpiH3bzHXgVI0MZU+3x/9Zg29Hnj7MKx8Yk\n"
				+ "ODUTwtQ5MjFPjbiFbjeZz6Fgh1T9ym2DOu3nD8a8KZSSvLJlXCKKGUmJlSMVwFv7\n"
				+ "Cvr+/8bMNAtBAhUA39iYchNZ3bgHEtsE+Li3lQw6o1UCgYBdcldZZpZ9SaSyfzy6\n"
				+ "ULwzLdkL45lYwMqgRuwNbRJtMFIr3CWsdYNZUyoUgWQM8DVNIlebUuXQ9/FM5VNI\n"
				+ "eZYvNdThmK/Lldf7KQ9+V/lLliWC3c8sI0wKHI7YR1tlnAo1plluTNjNVfu5g9q4\n"
				+ "O/PQmPAI6vfWxXO1uKorh8cDNAOBhAACgYBEknoqONBTiG+l3jbDhDIQfntaCCQb\n"
				+ "+SY6QeQCQtFCCNL70blTz6dkdFtJ2g6RKNlmBX3l3tZwR7lxuPUpI3WZveuGVzvW\n"
				+ "uxbbUtmBbWbMYSV9BWbeKJKuaOySpITmsSGZzk7n2y2+nzk7exNdN9JiTGLUGyq1\n" + "Ow2tfhD1WSbsDQ==\n"
				+ "-----END PUBLIC KEY-----";
		
		System.out.println(privateKey);
		System.out.println(publicKey);
		
		FileInputStream inputfile = new FileInputStream("/Users/aninath/Desktop/temp");
        byte[] inputfileVerify = new byte[inputfile.available()];
        inputfile.read(inputfileVerify);
        inputfile.close();

		//for (int i = 0; i < arr.length; i++) {
			try {
				byte[] ar = dsaPublicPrivateKeys.sign(inputfileVerify, privateKey, "SHA1withDSA");
				FileOutputStream fos = new FileOutputStream("/Users/aninath/Desktop/temp.sig");
				fos.write(ar);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		//}
		
		
		FileInputStream sigfis = new FileInputStream("/Users/aninath/Desktop/temp.sig");
        byte[] sigToVerify = new byte[sigfis.available()];
        sigfis.read(sigToVerify);
        sigfis.close();
        
        
        
        System.out.println(dsaPublicPrivateKeys.verifysign(inputfileVerify, sigToVerify, publicKey, "SHA1withDSA"));
		
		
		
		

	}
}
