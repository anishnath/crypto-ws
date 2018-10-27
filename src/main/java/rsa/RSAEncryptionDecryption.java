package rsa;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class RSAEncryptionDecryption {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public String encrypt(String param, String message, String algo) throws Exception {

	
		byte[] content = param.getBytes();
		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);

		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);

		Object obj = parser.readObject();

		System.out.println("Class-- " + obj.getClass());

		if(obj instanceof org.bouncycastle.cert.X509CertificateHolder)
		{
			X509CertificateHolder x509CertificateHolder = (org.bouncycastle.cert.X509CertificateHolder)obj;
			JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider("BC");
			X509Certificate x509Certificate =  jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
			PublicKey publicKey = x509Certificate.getPublicKey();
			String encryptedMessage = RSAUtil.encrypt(message, publicKey, algo);
			return encryptedMessage;
		}
		
		if (obj instanceof org.bouncycastle.jce.provider.JCERSAPublicKey) {
			JCERSAPublicKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPublicKey) obj;
			String encryptedMessage = RSAUtil.encrypt(message, jcersaPublicKey, algo);
			return encryptedMessage;
		}

		if (obj instanceof java.security.KeyPair) {
			KeyPair kp = (KeyPair) obj;
			String encryptedMessage = RSAUtil.encrypt(message, kp.getPrivate(), algo);
			return encryptedMessage;
		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) {

			BCRSAPublicKey bcrsaPublicKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) obj;
			String encryptedMessage = RSAUtil.encrypt(message, bcrsaPublicKey, algo);
			return encryptedMessage;

		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) {
			BCRSAPrivateKey bcrsaPrivateKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) obj;
			String encryptedMessage = RSAUtil.encrypt(message, bcrsaPrivateKey, algo);
			return encryptedMessage;

		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) {
			BCRSAPrivateCrtKey bcrsaPrivateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) obj;
			String encryptedMessage = RSAUtil.encrypt(message, bcrsaPrivateCrtKey, algo);
			return encryptedMessage;

		}

		if (obj instanceof org.bouncycastle.jce.provider.JCERSAPrivateKey) {
			JCERSAPrivateKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPrivateKey) obj;
			String encryptedMessage = RSAUtil.encrypt(message, jcersaPublicKey, algo);
			return encryptedMessage;
		}

		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			SubjectPublicKeyInfo subjectPublicKeyInfo = (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) obj;
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) obj);
			String encryptedMessage = RSAUtil.encrypt(message, publicKey, algo);
			return encryptedMessage;

		}
		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
			org.bouncycastle.openssl.PEMKeyPair keyPair = (org.bouncycastle.openssl.PEMKeyPair) obj;
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo)obj);
			String encryptedMessage = RSAUtil.encrypt(message, privateKey, algo);
			return encryptedMessage;			
		}
		

		throw new Exception("Not Able to Determine PemParser Object");

	}

	public String decrypt(String param, String message, String algo) throws Exception {
		byte[] content = param.getBytes();
		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);

		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);

		Object obj = parser.readObject();
		
		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			SubjectPublicKeyInfo subjectPublicKeyInfo = (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) obj;
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) obj);
			String encryptedMessage = RSAUtil.decrypt(message, publicKey, algo);
			return encryptedMessage;

		}
		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
			org.bouncycastle.openssl.PEMKeyPair keyPair = (org.bouncycastle.openssl.PEMKeyPair) obj;
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo)keyPair.getPrivateKeyInfo());
			String encryptedMessage = RSAUtil.decrypt(message, privateKey, algo);
			return encryptedMessage;			
		}

		if (obj instanceof org.bouncycastle.jce.provider.JCERSAPrivateKey) {
			JCERSAPrivateKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPrivateKey) obj;
			String encryptedMessage = RSAUtil.decrypt(message, jcersaPublicKey, algo);
			return encryptedMessage;
		}

		if (obj instanceof org.bouncycastle.jce.provider.JCERSAPublicKey) {
			JCERSAPublicKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPublicKey) obj;
			String encryptedMessage = RSAUtil.decrypt(message, jcersaPublicKey, algo);
			return encryptedMessage;
		}

		if (obj instanceof java.security.KeyPair) {
			KeyPair kp = (KeyPair) obj;
			String encryptedMessage = RSAUtil.decrypt(message, kp.getPrivate(), algo);
			return encryptedMessage;
		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) {

			BCRSAPublicKey bcrsaPublicKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) obj;
			String encryptedMessage = RSAUtil.decrypt(message, bcrsaPublicKey, algo);
			return encryptedMessage;

		}

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) {
			BCRSAPrivateKey bcrsaPrivateKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) obj;
			String encryptedMessage = RSAUtil.decrypt(message, bcrsaPrivateKey, algo);
			return encryptedMessage;

		}
		
		if(obj instanceof org.bouncycastle.cert.X509CertificateHolder)
		{
			X509CertificateHolder x509CertificateHolder = (org.bouncycastle.cert.X509CertificateHolder)obj;
			JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider("BC");
			X509Certificate x509Certificate =  jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
			PublicKey publicKey = x509Certificate.getPublicKey();
			String encryptedMessage = RSAUtil.decrypt(message, publicKey, algo);
			return encryptedMessage;
		}

		throw new Exception("Not Able to Determine PemParser Object");

	}
	
	
	public String signMessage(String param, String message, String algo) throws Exception
	{
		
		if(param.contains("BEGIN") && param.contains("PRIVATE"))
		{
			
			byte[] content = param.getBytes();
			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);
			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();
			
			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Private Key, Input key is Public Key");
			}
			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				org.bouncycastle.openssl.PEMKeyPair keyPair = (org.bouncycastle.openssl.PEMKeyPair) obj;
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo)keyPair.getPrivateKeyInfo());
				String signedMessage = RSAUtil.sign(message, privateKey, algo);
				return signedMessage;
				
			}

			if (obj instanceof org.bouncycastle.jce.provider.JCERSAPrivateKey) {
				JCERSAPrivateKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPrivateKey) obj;
				String signedMessage = RSAUtil.sign(message, jcersaPublicKey, algo);
				return signedMessage;
			}

			if (obj instanceof org.bouncycastle.jce.provider.JCERSAPublicKey) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Private Key");
			}

			if (obj instanceof java.security.KeyPair) {
				KeyPair kp = (KeyPair) obj;
				String signedMessage = RSAUtil.sign(message, kp.getPrivate(), algo);
				return signedMessage;
			}

			if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Private Key");

			}

			if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) {
				BCRSAPrivateKey bcrsaPrivateKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) obj;
				String signedMessage = RSAUtil.sign(message,bcrsaPrivateKey, algo);
				return signedMessage;

			}
			
			if(obj instanceof org.bouncycastle.cert.X509CertificateHolder)
			{
				throw new Exception("For RSA Signing Message Pleaee provide RSA Private Key, Input key is X.509 Key");
			}

			throw new Exception("Not Able to Determine PemParser Object");
			
		}
		
		PrivateKey pv = RSAUtil.getPrivateKeyFromString(param);
		
		if(pv!=null)
		{
			String signedMessage = RSAUtil.sign(message,pv, algo);
			return signedMessage;
			
		}
		else {
			throw new Exception("Failed to Sign the Message, Somethign Went Wrong, check the supplied Input");
		}
		
		
	}
	
	
	
	public boolean verifyMessage(String param, String message, String signature, String algo) throws Exception
	{
		
		if(param.contains("BEGIN") && param.contains("PUBLIC"))
		{
			
			byte[] content = param.getBytes();
			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);
			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();
			
			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				
				SubjectPublicKeyInfo subjectPublicKeyInfo = (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
				PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) obj);
				
				boolean ret=  RSAUtil.verify(message, signature, publicKey, algo);
				return ret;
			}
			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Public Key, Input key is Private Key");
				
			}

			if (obj instanceof org.bouncycastle.jce.provider.JCERSAPrivateKey) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Public Key, Input key is Private Key");
			}

			if (obj instanceof org.bouncycastle.jce.provider.JCERSAPublicKey) {
				JCERSAPublicKey jcersaPublicKey = (org.bouncycastle.jce.provider.JCERSAPublicKey) obj;
				boolean ret=  RSAUtil.verify(message, signature, jcersaPublicKey, algo);
				return ret;
				
			}

			if (obj instanceof java.security.KeyPair) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Public Key, Input key is Private Key");
			}

			if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Private Key");

			}

			if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey) {
				throw new Exception("For RSA Signing Message Pleaee provide RSA Public Key, Input key is Private Key");

			}
			
			if(obj instanceof org.bouncycastle.cert.X509CertificateHolder)
			{
				X509CertificateHolder x509CertificateHolder = (org.bouncycastle.cert.X509CertificateHolder)obj;
				JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider("BC");
				X509Certificate x509Certificate =  jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
				PublicKey publicKey = x509Certificate.getPublicKey();
				boolean ret=  RSAUtil.verify(message, signature, publicKey, algo);
				return ret;
				
			}

			throw new Exception("Not Able to Determine PemParser Object");
			
		}
		
		PublicKey pk = RSAUtil.getPublicKeyFromString(param);
		
		if(pk!=null)
		{
			boolean ret=  RSAUtil.verify(message, signature, pk, algo);
			return ret;
			
		}
		else {
			throw new Exception("Failed to Verify the Message, Somethign Went Wrong, check the supplied Input");
		}
		
		
	}

}
