package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import cacerts.Utils;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class PemParser {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public Object parsePemFileObject(final String data) throws Exception {
		return parsePemFileObject(data, null);
	}

	public Object parsePemFileObject(final String data, final String password) throws Exception {

		try {
			
			
			if (data == null || data.isEmpty()) {
				throw new Exception("Input PEM Data is Missing");
			}
			
			byte[] content = data.trim().getBytes();

			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);

			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();

			
			StringBuilder builder = new StringBuilder();

			if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
				PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) obj;

				InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
						.build(password.toCharArray());

				PrivateKeyInfo privateKeyinfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyinfo);
				
				return privateKey;
			}
			
			if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				
				return privateKey;
			}
			
			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				return privateKey;
			}
			
			
			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				return publickey;
			}
			
			if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
				X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
				byte[] x509 = certificateHolder.getEncoded();
				CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
				X509Certificate cert = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(x509));
				return cert;
			}
			

			if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
				PrivateKeyInfo keyInfo = (PrivateKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(keyInfo);
				return privateKey;
			}
			
			
			
			
			throw new Exception("Not Able to Determine PEM Parser Object");
			

		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public String parsePemFile(final String data) throws Exception {
		return parsePemFile(data, null);
	}

	public String parsePemFile(final String data, final String password) throws Exception {

		try {
			if (data == null || data.isEmpty()) {
				throw new Exception("Input PEM Data is Missing");
			}

			byte[] content = data.trim().getBytes();

			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);

			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();

			System.out.println("PemParser Class1-- " + obj.getClass());
			StringBuilder builder = new StringBuilder();

			if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
				PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) obj;

				InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
						.build(password.toCharArray());

				PrivateKeyInfo privateKeyinfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyinfo);
				builder.append("\n Private Key algo " + privateKey.getAlgorithm());
				builder.append("\n Private Format  " + privateKey.getFormat());

				String temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(privateKey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);
				return builder.toString();

			}

			if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				builder.append("\n Private Key algo " + privateKey.getAlgorithm());
				builder.append("\n Private Format  " + privateKey.getFormat());

				String temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(privateKey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				builder.append("\nPublic Key Information-----\n");
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				builder.append("\nAlgo " + publickey.getAlgorithm());
				builder.append("\nFormat " + publickey.getFormat());
				temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(publickey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				return builder.toString();

			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				builder.append("\n Private Key algo " + privateKey.getAlgorithm());
				builder.append("\n Private Format  " + privateKey.getFormat());

				String temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(privateKey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				builder.append("\nPublic Key Information-----\n");
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				builder.append("\nAlgo " + publickey.getAlgorithm());
				builder.append("\nFormat " + publickey.getFormat());
				temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(publickey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				return builder.toString();
			}

			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				builder.append("\nAlgo " + publickey.getAlgorithm());
				builder.append("\nFormat " + publickey.getFormat());
				String temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(publickey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				return builder.toString();

			}

			if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
				X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
				byte[] x509 = certificateHolder.getEncoded();
				CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
				X509Certificate cert = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(x509));
				return cert.toString();

			}

			if (obj instanceof org.bouncycastle.cert.X509CRLHolder) {
				X509CRLHolder holder = (X509CRLHolder) obj;
				JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
				X509CRL crl = converter.getCRL(holder);
				return crl.toString();
			}

			if (obj instanceof org.bouncycastle.asn1.cms.ContentInfo) {
				ContentInfo contentInfo = (ContentInfo) obj;
				builder.append("\n" + ASN1Dump.dumpAsString(contentInfo.getContent(), true));
				return builder.toString();

			}

			if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
				PrivateKeyInfo keyInfo = (PrivateKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(keyInfo);
				builder.append("\n Private Key algo " + privateKey.getAlgorithm());
				builder.append("\n Private Format  " + privateKey.getFormat());

				String temp = ASN1Dump.dumpAsString(ASN1Dump.dumpAsString(privateKey, true));
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());

				}
				builder.append("\n ASN1 Dump\n" + temp);

				return builder.toString();

			}

			if (obj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest) {
				PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest) obj;
				JcaPKCS10CertificationRequest certificationRequest2 = new JcaPKCS10CertificationRequest(
						certificationRequest);
				X500Name x500Name = certificationRequest2.getSubject();

				builder.append("Subject: " + x500Name.toString());
				builder.append("\nAlgo: " + certificationRequest2.getPublicKey().getAlgorithm());
				Attribute[] attributes = certificationRequest2.getAttributes();
				for (int i = 0; i < attributes.length; i++) {
					builder.append("\nAttributes " + attributes[i]);
				}

				builder.append("\nSingature: Hex Encoded " + Utils.toHexEncoded(certificationRequest2.getSignature()));

				String temp = ASN1Dump.dumpAsString(certificationRequest2.toASN1Structure(), true);
				if (temp != null && temp.contains("unknown object type")) {
					temp = temp.substring(40, temp.length());
				}
				builder.append("\n ASN1 Dump\n" + temp);
				return builder.toString();
			}

			throw new Exception("Not Able to Determine PEM Parser Object");

		} catch (Exception e) {
			throw new Exception(e);
		}
	}
	
	public String extractPublicKey(final String data, final String password) throws Exception {

		try {
			if (data == null || data.isEmpty()) {
				throw new Exception("Input PEM Data is Missing");
			}

			byte[] content = data.trim().getBytes();

			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);

			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();

			//System.out.println("PemParser Class-- " + obj.getClass());
			StringBuilder builder = new StringBuilder();

			if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
				PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) obj;

				InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
						.build(password.toCharArray());

				PrivateKeyInfo privateKeyinfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyinfo);
				
				PublicKey publickey;
				
				try{
					//First Try RSA
					BCRSAPrivateCrtKey privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) privateKey;
					RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateCrtKey.getModulus(),
							privateCrtKey.getPublicExponent());

					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					publickey = keyFactory.generatePublic(publicKeySpec);
					return Utils.toPem(publickey);
					
				}catch(Exception ex)
				{
					//Then  Try EC
					
					try
					{
					BCECPrivateKey  privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)obj;
					ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) privateCrtKey.getParams();
					ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecNamedCurveSpec.getGenerator(),ecNamedCurveSpec);
					KeyFactory keyFactory = KeyFactory.getInstance("EC");
					publickey = keyFactory.generatePublic(publicKeySpec);
					return Utils.toPem(publickey);
					}catch(Exception e)
					{
						try {
							//Finally Try DSA
							DSAPrivateKey dsa = (DSAPrivateKey) privateKey;
							DSAParams params = dsa.getParams();
							BigInteger g = params.getG();
							BigInteger p = params.getP();
							BigInteger q = params.getQ();
							BigInteger x = dsa.getX();
							BigInteger y = q.modPow( x, p );
							DSAPublicKeySpec dsaKeySpec = new DSAPublicKeySpec(y, p, q, g);
							publickey = KeyFactory.getInstance("DSA").generatePublic(dsaKeySpec);
							return Utils.toPem(publickey);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							throw new Exception("Not Able to Determine PEM Parser Object");
						}
					}
				}

			}

			if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				return Utils.toPem(publickey);
				

			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);				
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				return Utils.toPem(publickey);
				
				
			}


			if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
				PrivateKeyInfo keyInfo = (PrivateKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(keyInfo);
				
				PublicKey publickey;
				
				try{
					//First Try RSA
					BCRSAPrivateCrtKey privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) privateKey;
					RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateCrtKey.getModulus(),
							privateCrtKey.getPublicExponent());

					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					publickey = keyFactory.generatePublic(publicKeySpec);
					return Utils.toPem(publickey);
					
				}catch(Exception ex)
				{
					//Then  Try EC
					
					try
					{
					BCECPrivateKey  privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)obj;
					ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) privateCrtKey.getParams();
					ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecNamedCurveSpec.getGenerator(),ecNamedCurveSpec);
					KeyFactory keyFactory = KeyFactory.getInstance("EC");
					publickey = keyFactory.generatePublic(publicKeySpec);
					return Utils.toPem(publickey);
					}catch(Exception e)
					{
						try {
							//Finally Try DSA
							DSAPrivateKey dsa = (DSAPrivateKey) privateKey;
							DSAParams params = dsa.getParams();
							BigInteger g = params.getG();
							BigInteger p = params.getP();
							BigInteger q = params.getQ();
							BigInteger x = dsa.getX();
							BigInteger y = q.modPow( x, p );
							DSAPublicKeySpec dsaKeySpec = new DSAPublicKeySpec(y, p, q, g);
							publickey = KeyFactory.getInstance("DSA").generatePublic(dsaKeySpec);
							return Utils.toPem(publickey);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							throw new Exception("Not Able to Determine PEM Parser Object");
						}
					}
				}
				
				

			}

			

			throw new Exception("Not Able to Determine PEM Parser Object");

		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static void main(String[] args) throws Exception {
		
		KeyPair kp = Utils.generateRSAKeyPair("DSA", 1024);
		//System.out.println(Utils.toPem(kp));
		
		//System.exit(0);

		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("ec.key"));
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
		PemParser parser = new PemParser();
		try {
			String x = parser.extractPublicKey(everything, "123456");
			System.out.println(x);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
