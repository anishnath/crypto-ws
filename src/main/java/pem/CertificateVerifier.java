package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import cacerts.Utils;
import pojo.certpojo;

public class CertificateVerifier {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public certpojo verifyCertificate(String  certInfo, String privatekey) throws Exception
	{
		if(null == privatekey || privatekey.trim().length()==0 )
		{
			throw new Exception("PEM is Empty or NULL");
		}
		
		
		byte[] content = privatekey.trim().getBytes();
		PrivateKey pk =  null;
		KeyPair kp  =  null;
		RSAPublicKey rsaPublicKey  = null;
		X509Certificate cert = null;

		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);
		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);
		Object obj = parser.readObject();		
		
		
		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair)
		{
			PEMKeyPair pemKeyPair = (PEMKeyPair)obj;
			PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
			pk =  jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			kp  = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
			if (!(kp.getPrivate() instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Key file does not contain an X509 encoded private key" +  kp.getClass().getName());
            }
		}
		
		if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
			X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
			byte[] x509 = certificateHolder.getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(x509));
			
			if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Certificate file does not contain an RSA public key but a " + cert.getPublicKey().getClass().getName());
            }
			rsaPublicKey = (RSAPublicKey) cert.getPublicKey();

		}
		
		if (obj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest)
		{
			PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest)obj;
			JcaPKCS10CertificationRequest certificationRequest2 = new JcaPKCS10CertificationRequest(certificationRequest);
			
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
			PublicKey publickey = jcaPEMKeyConverter.getPublicKey(certificationRequest2.getSubjectPublicKeyInfo());
			if (!(publickey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("CSR file does not contain an RSA public key but a " + cert.getPublicKey().getClass().getName());
            }
			rsaPublicKey = (RSAPublicKey) certificationRequest2.getPublicKey();
			
		}
		
		content = certInfo.trim().getBytes();
		is = new ByteArrayInputStream(content);
		isr = new InputStreamReader(is);
		br = new BufferedReader(isr);
		parser = new PEMParser(br);
		obj = parser.readObject();
		
		
		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair)
		{
			PEMKeyPair pemKeyPair = (PEMKeyPair)obj;
			PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
			pk =  jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			kp  = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
			if (!(kp.getPrivate() instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Key file does not contain an X509 encoded private key" +  kp.getClass().getName());
            }
		}
		
		if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
			X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
			byte[] x509 = certificateHolder.getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(x509));
			
			if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Certificate file does not contain an RSA public key but a " + cert.getPublicKey().getClass().getName());
            }
			
			rsaPublicKey = (RSAPublicKey) cert.getPublicKey();

		}
		
		if (obj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest)
		{
			PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest)obj;
			JcaPKCS10CertificationRequest certificationRequest2 = new JcaPKCS10CertificationRequest(certificationRequest);
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
			PublicKey publickey = jcaPEMKeyConverter.getPublicKey(certificationRequest2.getSubjectPublicKeyInfo());
			if (!(publickey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("CSR file does not contain an RSA public key but a " + cert.getPublicKey().getClass().getName());
            }
			rsaPublicKey = (RSAPublicKey) certificationRequest2.getPublicKey();
			
		}
		

			if (rsaPublicKey ==null  )
			{
				throw new Exception("Failed to Validate Certificate Certificate Object Not Validated " + obj );
			}
			
			if (pk ==null )
			{
				throw new Exception("Failed to Validate Certificate Against Private Key private key Null " + obj );
			}
						
            final byte[] certModulusData = rsaPublicKey.getModulus().toByteArray();
            
            final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            final byte[] certID = sha1.digest(certModulusData);
            final String certIDinHex = Utils.toHexEncoded(certID);
            
            final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) pk;
            final byte[] keyModulusData = rsaPrivateKey.getModulus().toByteArray();
            final byte[] keyID = sha1.digest(keyModulusData);
            final String keyIDinHex = Utils.toHexEncoded(keyID);
            
            certpojo certpojo = new certpojo();
            
            if (certIDinHex.equalsIgnoreCase(keyIDinHex)) {
            	certpojo.setMessage("Match");
            	certpojo.setMessage2(certIDinHex);
            	certpojo.setMessage3(keyIDinHex);
            }
            else {
            	certpojo.setMessage("Failed");
            	certpojo.setMessage2(certIDinHex);
            	certpojo.setMessage3(keyIDinHex);
            }
			return certpojo;
			
	}
	
	public static void main(String[] args) throws Exception {


		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("csr.txt"));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			everything = sb.toString();
		} finally {
			br.close();
		}
		
		String privatekey=null;
		
		br = new BufferedReader(new FileReader("rsa.key"));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			privatekey = sb.toString();
		} finally {
			br.close();
		}
		CertificateVerifier  parser = new CertificateVerifier();
		try {
			certpojo x = parser.verifyCertificate(everything, privatekey);
			System.out.println(x);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

}
