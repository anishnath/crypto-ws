package ec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import cacerts.Utils;
import pojo.EncodedMessage;
import pojo.ecpojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */
public class EllipticCurve {

	public static byte[] iv = new SecureRandom().generateSeed(16);

	public EllipticCurve() {

	}

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public ecpojo generateKeyPair(final String ec_name) {
		
		try {
			ecpojo ecpojo = new ecpojo();
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
			kpgen.initialize(new ECGenParameterSpec(ec_name), new SecureRandom());
			KeyPair pairA = kpgen.generateKeyPair();
			ecpojo.setEcprivateKeyA(Utils.toPem(pairA));
			ecpojo.setEcpubliceKeyA(Utils.toPem(pairA.getPublic()));
			return ecpojo;
			
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
public ecpojo generateKeyPairECDSA(final String ec_name) {
		
		try {
			ecpojo ecpojo = new ecpojo();
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", "BC");
			kpgen.initialize(new ECGenParameterSpec(ec_name), new SecureRandom());
			KeyPair pairA = kpgen.generateKeyPair();
			ecpojo.setEcprivateKeyA(Utils.toPem(pairA));
			ecpojo.setEcpubliceKeyA(Utils.toPem(pairA.getPublic()));
			return ecpojo;
			
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public String signMessage (final String param,final String message , final String algo ) throws Exception
	{
		
		byte[] content = param.getBytes();
		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);

		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);

		Object obj = parser.readObject();

		
		
		
		
		PrivateKey thePrivKeyofA = null;

		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			throw new Exception("EC private Key Required for Signature Generation, Given EC Public Key");
		}

		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
			// System.out.println("Here--2");
			PEMKeyPair kp = (PEMKeyPair) obj;
			PrivateKeyInfo info = kp.getPrivateKeyInfo();
			thePrivKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(info);
			
			Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
			ecdsaSign.initSign(thePrivKeyofA);
			ecdsaSign.update(message.getBytes("UTF-8"));
			byte[] signature = ecdsaSign.sign();
			String sig =  Utils.toBase64Encode(signature);
			
			return sig;
		}
		
		throw new Exception("The Supplied Key is not Valid EC");
		
		
	}
	
	public boolean verifyMessage (final String param,final String message , final String signature , final String algo ) throws Exception
	{
		
		byte[] content = param.getBytes();
		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);

		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);

		Object obj = parser.readObject();

		//System.out.println("Class-- " + obj.getClass());
		
		
		
		PrivateKey thePrivKeyofA = null;
		PublicKey thepubKeyofA = null;

		if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
			SubjectPublicKeyInfo eckey = (SubjectPublicKeyInfo) obj;
			thepubKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(eckey);
			Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
			ecdsaVerify.initVerify(thepubKeyofA);
			ecdsaVerify.update(message.getBytes());
			boolean result = ecdsaVerify.verify(Utils.decodeBASE64(signature));
			return result;
			
		}

		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
			throw new Exception("EC public Key Required for Verification Given key is EC private Key");
		}
		return false;
		
	}

	public ecpojo generateKeyABPairSharedSecret(final String ec_name) {
		try {
			ecpojo ecpojo = new ecpojo();
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
			kpgen.initialize(new ECGenParameterSpec(ec_name), new SecureRandom());
			KeyPair pairA = kpgen.generateKeyPair();
			KeyPair pairB = kpgen.generateKeyPair();

			ecpojo.setEcprivateKeyA(Utils.toPem(pairA));
			ecpojo.setEcprivateKeyB(Utils.toPem(pairB));

			ecpojo.setEcpubliceKeyA(Utils.toPem(pairA.getPublic()));
			ecpojo.setEcpubliceKeyB(Utils.toPem(pairB.getPublic()));

			ECPrivateKey ecPrivkey = (ECPrivateKey) pairA.getPrivate();
			ECPublicKey eckey = (ECPublicKey) pairB.getPublic();

			doECDH(ecPrivkey.getD().toByteArray(), eckey.getQ().getEncoded(true), ec_name, ecpojo, true);

			ecPrivkey = (ECPrivateKey) pairB.getPrivate();
			eckey = (ECPublicKey) pairA.getPublic();

			doECDH(ecPrivkey.getD().toByteArray(), eckey.getQ().getEncoded(true), ec_name, ecpojo, false);

			return ecpojo;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	public EncodedMessage encryptDecryptMessage(String aPrivateKey, String bpublicKey, String plainText, String algo,
			 String encryptDecryptparam) throws Exception {

		EncodedMessage encodedMessage = new EncodedMessage();
		try {

			byte[] content = aPrivateKey.getBytes();
			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);
			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();

			PublicKey thepubKeyofA = null;
			PrivateKey thePrivKeyofA = null;

			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo eckey = (SubjectPublicKeyInfo) obj;
				thepubKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(eckey);
			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				// System.out.println("Here--2");
				PEMKeyPair kp = (PEMKeyPair) obj;
				PrivateKeyInfo info = kp.getPrivateKeyInfo();
				thePrivKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(info);
			}

			content = bpublicKey.getBytes();
			is = new ByteArrayInputStream(content);
			isr = new InputStreamReader(is);
			br = new BufferedReader(isr);
			parser = new PEMParser(br);
			obj = parser.readObject();

			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				// System.out.println("Here--3");
				SubjectPublicKeyInfo eckey = (SubjectPublicKeyInfo) obj;
				thepubKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(eckey);

			}

			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair kp = (PEMKeyPair) obj;
				PrivateKeyInfo info = kp.getPrivateKeyInfo();
				thePrivKeyofA = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(info);

			}

			if (thepubKeyofA != null && thePrivKeyofA != null) {

				SecretKey secretKey = Utils.generateSharedSecret(thePrivKeyofA, thepubKeyofA);

				SecureRandom random = new SecureRandom();
				byte bytes[] = new byte[16];
				random.nextBytes(bytes);

				if ("encrypt".equals(encryptDecryptparam)) {

					if (secretKey != null) {
						byte b[] = null;

						IvParameterSpec inspec = new IvParameterSpec(bytes);
						b = Utils.encryptString(secretKey, plainText, algo, inspec.getIV());
						
						byte[] buffer =  new byte[bytes.length + b.length];
						
						System.arraycopy(bytes, 0, buffer, 0, bytes.length);
						System.arraycopy(b, 0, buffer, bytes.length, b.length);
						
						encodedMessage.setIntialVector(Utils.toHexEncoded(inspec.getIV()));
						encodedMessage.setBase64Encoded(Utils.toBase64Encode(buffer));

						return encodedMessage;

					} else {
						throw new Exception("Failed to Generate Secret Key....");
					}
				} else if ("decrypt".equals(encryptDecryptparam)) {
					
					byte b[] = Utils.decryptString(secretKey, plainText, algo);
					encodedMessage.setMessage(new String(b));
					return encodedMessage;
				}
			} else {
				throw new Exception("Private Key of A , Public Key of B is required...");
			}

		} catch (Exception e) {
			throw new Exception(e);
			// return null;
		}
		return null;
	}

	private void doECDH(byte[] dataPrv, byte[] dataPub, final String ec_name, ecpojo ecpojo, boolean A)
			throws Exception {
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(ec_name);
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(dataPrv), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		ka.init(kf.generatePrivate(prvkey));
		ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(dataPub), params);
		ka.doPhase(kf.generatePublic(pubKey), true);
		byte[] secret = ka.generateSecret();
		if (A) {
			ecpojo.setShareSecretA(Utils.toBase64Encode(secret));
		}
		if (!A) {
			ecpojo.setShareSecretB(Utils.toBase64Encode(secret));
		}

	}

	public static List<String> getAllECNamedCurveName() {

		List<String> ecNames = new ArrayList<String>();
		Enumeration<String> e = ECNamedCurveTable.getNames();
		while (e.hasMoreElements()) {
			String param = e.nextElement();
			ecNames.add(param);
		}
		return ecNames;
	}

	public static void main(String[] args) throws Exception {

		String plainText = "Hello Anish Demo at 8gwifi.org!";
		// System.out.println("Original plaintext message: " + plainText);
		
		EllipticCurve curve1 = new EllipticCurve();
		
		ecpojo ecpojo1 = curve1.generateKeyPairECDSA("sect283k1");
		
		System.out.println(ecpojo1.getEcprivateKeyA());
		System.out.println(ecpojo1.getEcpubliceKeyA());
		
		String sig = curve1.signMessage(ecpojo1.getEcprivateKeyA(), "Hello 8gwifi.org","");
		boolean x = curve1.verifyMessage(ecpojo1.getEcpubliceKeyA(), "Hello 8gwifi.org",sig,"");
		
		System.out.println(x);
		System.out.println("Signature " + sig);
		
		//System.out.println("Signature " + sig);
		
		System.exit(0);

		String[] validList = { "c2pnb272w1", "c2tnb359v1", "prime256v1", "c2pnb304w1", "c2pnb368w1", "c2tnb431r1",
				"sect283r1", "sect283k1", "secp256k1", "secp256r1", "sect571r1", "sect571k1", "sect409r1", "sect409k1",
				"secp521r1", "secp384r1", "P-521", "P-256", "P-384", "B-409", "B-283", "B-571", "K-409", "K-283",
				"K-571", "brainpoolp512r1", "brainpoolp384t1", "brainpoolp256r1", "brainpoolp512t1", "brainpoolp256t1",
				"brainpoolp320r1", "brainpoolp384r1", "brainpoolp320t1", "FRP256v1", "sm2p256v1" };

		for (int i = 0; i < validList.length; i++) {

			String param = "";
			try {
				param = validList[i];
				// System.out.println(param);
				EllipticCurve curve = new EllipticCurve();
				ecpojo ecpojo = curve.generateKeyABPairSharedSecret(param);
				// System.out.println(iv.toString());
				// System.out.println(ecpojo);
				String algo = "AES/GCM/NoPadding";

				EncodedMessage m = curve.encryptDecryptMessage(ecpojo.getEcprivateKeyB(), ecpojo.getEcpubliceKeyA(),
						plainText, algo, "encrypt");
				 //System.out.println("Encrypt --\n" + m);
				
				 
				 EncodedMessage m1 = curve.encryptDecryptMessage(ecpojo.getEcprivateKeyA(), ecpojo.getEcpubliceKeyB(),
						m.getBase64Encoded(), algo, "decrypt");
				 
				 if(m1.getMessage().equals(plainText))
				 {
					 System.out.println("Sucess -- ");
				 }
				 else {
					 System.out.println("Failed.. -- ");
				 }

				 //System.out.println(m1);

				//m1 = curve.encryptDecryptMessage(ecpojo.getEcprivateKeyA(), ecpojo.getEcpubliceKeyB(),
					//	m.getHexEncoded(), algo, m.getIntialVector(), "decrypt");
				// System.out.println(m1);
				// m = curve.encryptDecryptMessage(ecpojo.getEcprivateKeyA(),
				// ecpojo.getEcpubliceKeyB(), plainText, algo, null, "encrypt");

				// System.out.println(m);

				// break;
				//System.out.println(param);
			} catch (Exception e1) {
				System.out.println("Failed --> " + param + e1);
			}

		}

	}
}