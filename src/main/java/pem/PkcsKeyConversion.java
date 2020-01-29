package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import cacerts.Utils;
import pojo.jwspojo;

public class PkcsKeyConversion {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public  String deterMineObjectAndSign(final String data,String password) throws Exception {


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
				
				if(data.contains("RSA PRIVATE") || data.contains("DSA PRIVATE") || data.contains("EC PRIVATE"))
				{
					PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
					return getPKCS1(pemObject);
				}
				return Utils.toPem(privateKey);
				
			}

			if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				
				if(data.contains("RSA PRIVATE") || data.contains("DSA PRIVATE") || data.contains("EC PRIVATE"))
				{
					PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
					return getPKCS1(pemObject);
				}
				return Utils.toPem(privateKey);
				
				

			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();

				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);		
				
				if(data.contains("RSA PRIVATE") || data.contains("DSA PRIVATE") || data.contains("EC PRIVATE"))
				{
					PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
					return getPKCS1(pemObject);
				}
				return Utils.toPem(privateKey);
				
			}


			if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
				PrivateKeyInfo keyInfo = (PrivateKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(keyInfo);
				
				if(data.contains("RSA PRIVATE") || data.contains("DSA PRIVATE") || data.contains("EC PRIVATE"))
				{
					PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
					return getPKCS1(pemObject);
				}
				return Utils.toPem(privateKey);
				
			}

			

			throw new Exception("Not Able to Determine PEM Parser Object");

		} catch (Exception e) {
			throw new Exception(e);
		}
	
	}

	public String getPKCS1(PemObject privateKey) throws IOException {
		StringWriter str = new StringWriter();
		PEMWriter pemWriter = new PEMWriter(str);
		pemWriter.writeObject(privateKey);
		pemWriter.close();
		str.close();
		return str.toString();
	}
	
public static void main(String[] args) throws Exception {
		
		//KeyPair kp = Utils.generateRSAKeyPair("DSA", 1024);
		//System.out.println(Utils.toPem(kp));
		
		//System.exit(0);

		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("ec1.key"));
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
		
		PkcsKeyConversion dete = new PkcsKeyConversion();
		try {
			String x = dete.deterMineObjectAndSign(everything,null);
			System.out.println(x);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
