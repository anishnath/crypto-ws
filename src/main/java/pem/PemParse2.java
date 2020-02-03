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
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Integers;

import com.amazonaws.adapters.types.StringToByteBufferAdapter;
import com.google.protobuf.Extension;

import cacerts.Utils;
import cipher.MessageDigestCalc;
import pojo.EncodedMessage;
import pojo.dsapojo;
import pojo.eckeypojo;
import pojo.rsapojo;
import pojo.x509pojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class PemParse2 {

	public static final String NEWLINE = "\n";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}


	
	public EncodedMessage parsePemFile(final String data) throws Exception {
		return parsePemFile(data, null);
	}

	public EncodedMessage parsePemFile(final String data, final String password) throws Exception {

		EncodedMessage encodedMessage = new EncodedMessage();

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
				encodedMessage.setMessage(builder.toString());
				
				giveMePEMString(encodedMessage, privateKey);
				return encodedMessage;
				
				

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

				encodedMessage.setMessage(builder.toString());
				
				giveMePEMString(encodedMessage, privateKey);
				
		
				
				return encodedMessage;

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

				encodedMessage.setMessage(builder.toString());
				
				giveMePEMString(encodedMessage, privateKey);
				
				return encodedMessage;
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

				encodedMessage.setMessage(builder.toString());
				return encodedMessage;

			}

			if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {

				x509pojo x509pojo = new x509pojo();

				X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
				byte[] x509 = certificateHolder.getEncoded();
				CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
				X509Certificate cert = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(x509));

				x509pojo.setType(cert.getType());
				x509pojo.setVersion(String.valueOf(cert.getVersion()));
				x509pojo.setSerialNumber(Utils.encodeHex(cert.getSerialNumber().toByteArray(), ":") + " ("
						+ cert.getSerialNumber() + ")");
				x509pojo.setSigAlgName(cert.getSigAlgName() + "(" + cert.getSigAlgOID() + ")");
				x509pojo.setNotBefore(String.valueOf(cert.getNotBefore()));
				x509pojo.setNotAfter(String.valueOf(cert.getNotBefore()));
				if (cert.getSubjectDN() != null) {
					x509pojo.setSubjectDN(cert.getSubjectDN().getName());
				}

				if (cert.getIssuerDN() != null) {
					x509pojo.setIssuerDN(cert.getIssuerDN().getName());
				}

				x509pojo.setSignature(Utils.encodeHex(cert.getSignature(), ":"));
				x509pojo.setEncoded(Utils.encodeHex(cert.getEncoded(), ":"));

				// System.out.println(cert.getType());
				// System.out.println(cert.getVersion());
				// System.out.println(Utils.encodeHex(cert.getSerialNumber().toByteArray(),":")
				// + " (" +cert.getSerialNumber() +")");
				// System.out.println(cert.getSigAlgName());
				// cert.getSigAlgOID();
				// System.out.println(cert.getNotBefore());
				// System.out.println(cert.getNotAfter());
				// System.out.println("Subject DN " +
				// cert.getSubjectDN().getName());
				// System.out.println(cert.getIssuerDN().getName());
				//
				// System.out.println("Signature + "
				// +Utils.encodeHex(cert.getSignature(),":"));

				byte[] sha256 = MessageDigestCalc.calculateMessageDigest("sha-256", cert.getEncoded());
				// System.out.println(Utils.encodeHex(sha256,":"));

				x509pojo.setSha256(Utils.encodeHex(sha256, ":"));

				byte[] sha1 = MessageDigestCalc.calculateMessageDigest("sha-1", cert.getEncoded());
				// System.out.println(Utils.encodeHex(sha1,":"));

				x509pojo.setSha1(Utils.encodeHex(sha1, ":"));

				byte[] md5 = MessageDigestCalc.calculateMessageDigest("md5", cert.getEncoded());
				// System.out.println(Utils.encodeHex(md5,":"));

				x509pojo.setMd5(Utils.encodeHex(md5, ":"));

				// System.out.println(Utils.encodeHex(cert.getEncoded(),":"));

				if (cert.getSubjectAlternativeNames() != null) {
					StringBuilder builder1 = new StringBuilder();
					Iterator it = cert.getSubjectAlternativeNames().iterator();
					while (it.hasNext()) {
						// look for URI
						List list = (List) it.next();
						String temp = (String) list.get(1);
						builder1.append(temp);
						builder1.append("\n");
					}

					System.out.println(builder1.toString());
					x509pojo.setSubjectAlternativeNames(builder1.toString());
				}

				if (cert.getIssuerAlternativeNames() != null) {
					StringBuilder builder1 = new StringBuilder();
					Iterator it = cert.getIssuerAlternativeNames().iterator();
					while (it.hasNext()) {
						// look for URI
						List list = (List) it.next();
						String temp = (String) list.get(1);
						builder1.append(temp);
						builder1.append("\n");
					}

					System.out.println(builder1.toString());

				}

				try {
					if (cert.getCriticalExtensionOIDs() != null) {

						Set<String> criticalExternsionOid = cert.getCriticalExtensionOIDs();
						StringBuilder b = new StringBuilder();
						for (Iterator iterator = criticalExternsionOid.iterator(); iterator.hasNext();) {
							String string = (String) iterator.next();
							// System.out.println("string2 " + string);
							// System.out.println(cert.getExtensionValue(string));
							StringBuilder builder2 = new StringBuilder();

							ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(string);

							X509Ext ext = new X509Ext(oid, cert.getExtensionValue(string), true);
							if (ext != null) {
								b.append(ext.getStringValue());
							}

						}

						x509pojo.setCrticalExtensions(b.toString());

					}
				} catch (Exception e) {
					// TODO: handle exception
				}

				try {
					if (cert.getNonCriticalExtensionOIDs() != null) {
						StringBuilder builder2 = new StringBuilder();
						Set<String> criticalExternsionOid = cert.getNonCriticalExtensionOIDs();

						for (Iterator iterator = criticalExternsionOid.iterator(); iterator.hasNext();) {
							String string = (String) iterator.next();
							// System.out.println("string3 " + string);
							// Extensions.Keyusage

							ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(string);

							X509Ext ext = new X509Ext(oid, cert.getExtensionValue(string), false);
							if (ext != null) {
								builder2.append(ext.getStringValue());
							}
						}
						x509pojo.setNoncrticalExtensions(builder2.toString());

					}
				} catch (Exception ex) {
				}

				if (isSelfIssued(cert)) {
					x509pojo.setIsSelfSigned("Self Signed");
				} else {
					x509pojo.setIsSelfSigned("CA Signed");
				}

				encodedMessage.setX509(x509pojo);
				return encodedMessage;

			}

			if (obj instanceof org.bouncycastle.cert.X509CRLHolder) {
				X509CRLHolder holder = (X509CRLHolder) obj;
				JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
				X509CRL crl = converter.getCRL(holder);
				encodedMessage.setMessage(crl.toString());
				return encodedMessage;
			}

			if (obj instanceof org.bouncycastle.asn1.cms.ContentInfo) {
				ContentInfo contentInfo = (ContentInfo) obj;
				builder.append("\n" + ASN1Dump.dumpAsString(contentInfo.getContent(), true));
				encodedMessage.setMessage(builder.toString());
				return encodedMessage;

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

				encodedMessage.setMessage(builder.toString());
				return encodedMessage;

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
				encodedMessage.setMessage(builder.toString());
				return encodedMessage;
			}

			throw new Exception("Not Able to Determine PEM Parser Object");

		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public void giveMePEMString(EncodedMessage encodedMessage, PrivateKey privateKey) {
		PublicKey publickey;
		try{
			
			
			
			//First Try RSA
			BCRSAPrivateCrtKey privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) privateKey;
			rsapojo rsapojo = new rsapojo();
			rsapojo.setAlgo(privateCrtKey.getAlgorithm());
			rsapojo.setKeySize(String.valueOf(privateCrtKey.getModulus().bitLength()));
			rsapojo.setFormat(privateCrtKey.getFormat());
			rsapojo.setFingerprint(String.valueOf(new Fingerprint(Arrays.concatenate(privateCrtKey.getModulus().toByteArray(), privateCrtKey.getPublicExponent().toByteArray()))));
			rsapojo.setModulus(Utils.encodeHex(privateCrtKey.getModulus().toByteArray(), ":"));
			rsapojo.setCrtCoefficient(Utils.encodeHex(privateCrtKey.getCrtCoefficient().toByteArray(), ":"));
			rsapojo.setPrimeExponentP(Utils.encodeHex(privateCrtKey.getPrimeExponentP().toByteArray(), ":"));
			rsapojo.setPrimeExponentQ(Utils.encodeHex(privateCrtKey.getPrimeExponentQ().toByteArray(), ":"));
			rsapojo.setPrimeP(Utils.encodeHex(privateCrtKey.getPrimeP().toByteArray(), ":"));
			rsapojo.setPrimeQ(Utils.encodeHex(privateCrtKey.getPrimeQ().toByteArray(), ":"));
			rsapojo.setPrivateexponent(Utils.encodeHex(privateCrtKey.getPrivateExponent().toByteArray(), ":"));
			rsapojo.setPublicexponent(String.valueOf(privateCrtKey.getPublicExponent()));
			
//					System.out.println("11--" + privateCrtKey.getAlgorithm());
//					System.out.println("11--" + privateCrtKey.getFormat());
//					System.out.println("11--" + privateCrtKey.getCrtCoefficient());
//					System.out.println("11--" + privateCrtKey.getModulus().toString(16));
//					System.out.println("11--" + privateCrtKey.getPrimeExponentP());
//					System.out.println("11--" + Utils.encodeHex(privateCrtKey.getPrimeExponentP().toByteArray(), ":"));
//					System.out.println("11--" + privateCrtKey.getPrimeExponentQ());
//					System.out.println("11--" + privateCrtKey.getPrimeP());
//					System.out.println("11--" + privateCrtKey.getPrimeQ());
//					System.out.println("11--" + privateCrtKey.getPrivateExponent());
//					System.out.println("11--" + privateCrtKey.getPublicExponent().toString(16));
//					System.out.println("12--" + privateCrtKey.toString());
			
			
			byte[] sha256 = MessageDigestCalc.calculateMessageDigest("sha-256", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(sha256, ":"));
			rsapojo.setSha256(Utils.encodeHex(sha256, ":"));
			byte[] sha1 = MessageDigestCalc.calculateMessageDigest("sha-1", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(sha1, ":"));
			rsapojo.setSha1(Utils.encodeHex(sha1, ":"));
			byte[] md5 = MessageDigestCalc.calculateMessageDigest("md5", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(md5, ":"));
			rsapojo.setMd5(Utils.encodeHex(md5, ":"));
			
			rsapojo.setEncoded(Utils.encodeHex(privateCrtKey.getEncoded(), ":"));
			
			
			//System.out.println(Utils.encodeHex(privateCrtKey.getEncoded(), ":"));
			//System.out.println(rsapojo);
			//System.out.println(privateCrtKey.getModulus().bitLength());
			
			encodedMessage.setRsapojo(rsapojo);
			
			
			
		}catch(Exception ex)
		{
			
			try
			{
			BCECPrivateKey  privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)privateKey;
			
			eckeypojo eckeypojo = new eckeypojo();
			eckeypojo.setAlgo(privateCrtKey.getAlgorithm());
			eckeypojo.setFormat(privateCrtKey.getFormat());
			
			if(privateCrtKey.getParams()!=null)
			{
				if(privateCrtKey.getParams().getOrder()!=null)
				{
					eckeypojo.setKeySize(String.valueOf(privateCrtKey.getParams().getOrder().bitLength()));
				}
			}
			
			eckeypojo.setPrivateKey(String.valueOf(Utils.encodeHex(privateCrtKey.getD().toByteArray(),":")));
			
			
			
//					System.out.println(privateCrtKey);
//					System.out.println(privateCrtKey.getAlgorithm());
//					System.out.println(privateCrtKey.getFormat());
//					System.out.println(privateCrtKey.getParams().getOrder().bitLength());
//					
//					System.out.println("D " +Utils.encodeHex(privateCrtKey.getD().toByteArray(),":"));
//					System.out.println("S " +Utils.encodeHex(privateCrtKey.getS().toByteArray(),":"));
			
			ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) privateCrtKey.getParams();
			
			if(ecNamedCurveSpec!=null)
			{
				eckeypojo.setCurveName(ecNamedCurveSpec.getName());
				eckeypojo.setCofactor(String.valueOf(ecNamedCurveSpec.getCofactor()));
				eckeypojo.setAffineX(Utils.encodeHex(ecNamedCurveSpec.getGenerator().getAffineX().toByteArray(),":"));
				eckeypojo.setAffineY(Utils.encodeHex(ecNamedCurveSpec.getGenerator().getAffineY().toByteArray(),":"));
				eckeypojo.setOrder(Utils.encodeHex(ecNamedCurveSpec.getOrder().toByteArray(),":"));
			}
			
			
			
//					System.out.println(ecNamedCurveSpec.getName());
//					System.out.println(ecNamedCurveSpec.getCofactor());
//					//System.out.println(privateCrtKey.getD());
//					
//					System.out.println("X- " + ecNamedCurveSpec.getGenerator().getAffineX().toString(16));
//					System.out.println("Y- " + ecNamedCurveSpec.getGenerator().getAffineY().toString(16));
//					
//					System.out.println("HEX " + Utils.encodeHex(ecNamedCurveSpec.getGenerator().getAffineX().toByteArray(),":"));
//					System.out.println("HEY "+ Utils.encodeHex(ecNamedCurveSpec.getGenerator().getAffineY().toByteArray(),":"));
//					
//					System.out.println(Utils.encodeHex(ecNamedCurveSpec.getOrder().toByteArray(),":"));
//					
			//org.bouncycastle.math.ec.ECPoint ecpoint = calculateQ(privateCrtKey.getD(), ecNamedCurveSpec);
			
			//System.out.println(Utils.encodeHex(ecNamedCurveSpec.getGenerator().toString().getBytes(),":"));
			
			ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecNamedCurveSpec.getGenerator(),ecNamedCurveSpec);
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			publickey = keyFactory.generatePublic(publicKeySpec);
			eckeypojo.setPublicKey(Utils.encodeHex(publickey.getEncoded(),":"));
			//System.out.println(Utils.encodeHex(publickey.getEncoded(),":"));
			
			byte[] sha256 = MessageDigestCalc.calculateMessageDigest("sha-256", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(sha256, ":"));
			eckeypojo.setSha256(Utils.encodeHex(sha256, ":"));
			byte[] sha1 = MessageDigestCalc.calculateMessageDigest("sha-1", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(sha1, ":"));
			eckeypojo.setSha1(Utils.encodeHex(sha1, ":"));
			byte[] md5 = MessageDigestCalc.calculateMessageDigest("md5", privateCrtKey.getEncoded());
			//System.out.println(Utils.encodeHex(md5, ":"));
			eckeypojo.setMd5(Utils.encodeHex(md5, ":"));
			
			encodedMessage.setEckeypojo(eckeypojo);
			
			//System.out.println(eckeypojo);
			
			
			
			
			}catch(Exception ex1) {
				
				
				//Finally Try DSA
				
				try
				{
					
					
					DSAPrivateKey dsa = (DSAPrivateKey) privateKey;
					
					
					
					dsapojo dsapojo = new dsapojo();
					
					dsapojo.setAlgo(privateKey.getAlgorithm());
					dsapojo.setFormat(privateKey.getFormat());
					
					
					
					DSAParams params = dsa.getParams();
					
					if(params!=null)
					{
					
						BigInteger g = params.getG();
						BigInteger p = params.getP();
						BigInteger q = params.getQ();
						BigInteger x = dsa.getX();
						BigInteger y = q.modPow( x, p );
						
						dsapojo.setG(Utils.encodeHex(g.toByteArray(), ":"));
						dsapojo.setP(Utils.encodeHex(p.toByteArray(), ":"));
						dsapojo.setQ(Utils.encodeHex(q.toByteArray(), ":"));
						dsapojo.setX(Utils.encodeHex(x.toByteArray(), ":"));
						dsapojo.setY(Utils.encodeHex(y.toByteArray(), ":"));
						
						//System.out.println(Utils.encodeHex(privateKey.getEncoded(),":"));
						
						DSAPublicKeySpec dsaKeySpec = new DSAPublicKeySpec(y, p, q, g);
						publickey = KeyFactory.getInstance("DSA").generatePublic(dsaKeySpec);
						if(publickey!=null)
						{
							dsapojo.setPub(Utils.encodeHex(publickey.getEncoded(), ":"));
						}
					}
					
					dsapojo.setEncoded(Utils.encodeHex(privateKey.getEncoded(),":"));
					byte[] sha256 = MessageDigestCalc.calculateMessageDigest("sha-256", privateKey.getEncoded());
					//System.out.println(Utils.encodeHex(sha256, ":"));
					dsapojo.setSha256(Utils.encodeHex(sha256, ":"));
					byte[] sha1 = MessageDigestCalc.calculateMessageDigest("sha-1", privateKey.getEncoded());
					//System.out.println(Utils.encodeHex(sha1, ":"));
					dsapojo.setSha1(Utils.encodeHex(sha1, ":"));
					byte[] md5 = MessageDigestCalc.calculateMessageDigest("md5", privateKey.getEncoded());
					//System.out.println(Utils.encodeHex(md5, ":"));
					dsapojo.setMd5(Utils.encodeHex(md5, ":"));
					
					
					encodedMessage.setDsapojo(dsapojo);;
					
					
					
					
					
				}catch(Exception ex3){
					
					
				}
				
			}
			
		}
	}

	private org.bouncycastle.math.ec.ECPoint calculateQ(BigInteger d, org.bouncycastle.jce.spec.ECParameterSpec spec)
	  {
	        return spec.getG().multiply(d).normalize();
	   }

	protected static boolean isSelfIssued(X509Certificate cert) {
		return cert.getSubjectDN().equals(cert.getIssuerDN());
	}

	public static void main(String[] args) throws Exception {

		KeyPair kp = Utils.generateRSAKeyPair("DSA", 1024);
		// System.out.println(Utils.toPem(kp));

		// System.exit(0);

		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("dsa.key"));
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
		PemParse2 parser = new PemParse2();
		try {
			EncodedMessage x = parser.parsePemFile(everything, "123456");
			System.out.println(x);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	
}
