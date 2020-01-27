package jwk;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.UUID;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSObject.State;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import cacerts.Utils;
import pem.PemParser;
import pojo.jwspojo;

public class JWS {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		String pkcs8 = "-----BEGIN PRIVATE KEY-----\n"
				+ "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOrLOOMLoy7rv1\n"
				+ "PJOuiSDWJ8fxKyrIs2GnKf9OjLEtqEk8+3INwL5DBG4jOEtHYlusw1VtZ3cuN8+V\n"
				+ "ctqocvbe/0Q5hJ7yKz6IpKxdbQKux2LO02djVlzPNR037ghzsJBnEdh0jUhG6Z3k\n"
				+ "7WrQCNU4ynA+hm2+a+SoSd+GehQ4+jWEfldjuuZNYQyDQk9mR53bOWMYoQgG3WCZ\n"
				+ "G/DG4PAEq17Jy95QcN7v5+8flPB1WgcRs2wcJGs7VGmYF3lMbU+sJdUH/BKLIGzG\n"
				+ "V3sfoljMTuJzy4ZP3wEu9kYTSpX0PR9HjP5cijDTvdk4hr2/xo+7/ZAilu/rHSt7\n"
				+ "mA9FMCd/AgMBAAECggEBAIQiTjneVW0yzOChdhnkeiXxERfTbWsbpJdndl8V/EEg\n"
				+ "kpJ2gBji3cGjF3dVCmv9Kndt+zQTLlNSQ1ldMQb5WXSA53GOpMBXfYeHINwqUcjE\n"
				+ "mRt6dWNBV9zyLFgRyz2L6Qa8lhMOMOOFgPlYAS44N3ozk0emUouoF2ywrkQf0MYL\n"
				+ "q5T2xjEeoZMh6Hf9EaDa7FHIf3YK6RqMSCc5IPDuVYtm30aE7D8IesJz9QOF+GdP\n"
				+ "dXQ3sMLWwg6QxXGDsd/yOXFiSnTeFOYzDuzg0orkGOePbDIL/bRIecPD5ZTuZbxp\n"
				+ "fKByyndGGnLgYAPAe9dwkzjG/u3q028ES6KKW+sH9qECgYEA8uC/ots2DfWUyzcO\n"
				+ "rVVuhPbJSJbWsIRISGeY0BXet64Uu3XltE03SiIPlsQBhWIwcW+Fc2s60c//E/1Q\n"
				+ "gxeX05lOu6AT7rkAB9h2nUzhUS/kGq7pr0wasv4zSTSmGI5SWqmfXCJWozyktM06\n"
				+ "o+jzl21UpUsiRqFuWKnK926lPm0CgYEA2dc5TA59QKNwrx2WPDEUc+Y9zNkrlyQE\n"
				+ "1pPMcbHR0MEqO+rPP2vq8xjIiUm90hP4Qvt5I+iQOEo/+XrBRWpz6kWmnOsE/eO5\n"
				+ "FUhOA+a0ZVyUf9wyLEG7LVfBoqjmp5yd2gnIIFIZcQoRLo+DVfv+VUo5CWjPGi92\n"
				+ "G8cJJkXpmhsCgYB5Q09K72nYpGGq6I1Sa5InntO2g2EjdphkVh0M3654RNkjE2Uh\n"
				+ "lV/iioj//FLKFtEbAdQ+YS5X7SJtB4+4NAJg6m1N7kmlagai5Cest+LTVzbrP6N7\n"
				+ "G2NFNPfEOB4pqn1huMjRBm/9RlzxzHnXtopQc4zMjmvJmfXvHK8yxLKKLQKBgEe5\n"
				+ "T0o1cxP3PEDMEw0ac8t9QVfTIUEQQO+NlkDQ9W4wS4GS3E3bcG49+LkLKI6kuJcF\n"
				+ "SWuDRQjjmZDA1CXQ2P2HlUYRM4GMmwHg3p72NOsywkoe6/4aXlCdlknCJr+FF4wU\n"
				+ "sGnD3lCTqfiUk/+ZirH2UDVC5v2OJusaa27IkhOFAoGAV9+qE7tkZY6agxIpTJN6\n"
				+ "YonwvBI8lNYqI63GMrWDnC5UKg9YGPdY6E7O6ypp+F0k0WwjVzLRmJGxFx6AsrlV\n"
				+ "Z6Fo/LCPTNV/60Optvy145rJqSf/hFDWUgUFoN3TWighfxS7J1/TpOJm3i7XWKSM\n" + "8W/VNjocWoydvtRKOn4Z7Ts=\n"
				+ "-----END PRIVATE KEY-----\n";

		String rsaPrivatekey = "-----BEGIN RSA PRIVATE KEY-----\n"
				+ "MIIEowIBAAKCAQEAzqyzjjC6Mu679TyTrokg1ifH8SsqyLNhpyn/ToyxLahJPPty\n"
				+ "DcC+QwRuIzhLR2JbrMNVbWd3LjfPlXLaqHL23v9EOYSe8is+iKSsXW0CrsdiztNn\n"
				+ "Y1ZczzUdN+4Ic7CQZxHYdI1IRumd5O1q0AjVOMpwPoZtvmvkqEnfhnoUOPo1hH5X\n"
				+ "Y7rmTWEMg0JPZked2zljGKEIBt1gmRvwxuDwBKteycveUHDe7+fvH5TwdVoHEbNs\n"
				+ "HCRrO1RpmBd5TG1PrCXVB/wSiyBsxld7H6JYzE7ic8uGT98BLvZGE0qV9D0fR4z+\n"
				+ "XIow073ZOIa9v8aPu/2QIpbv6x0re5gPRTAnfwIDAQABAoIBAQCEIk453lVtMszg\n"
				+ "oXYZ5Hol8REX021rG6SXZ3ZfFfxBIJKSdoAY4t3Boxd3VQpr/Sp3bfs0Ey5TUkNZ\n"
				+ "XTEG+Vl0gOdxjqTAV32HhyDcKlHIxJkbenVjQVfc8ixYEcs9i+kGvJYTDjDjhYD5\n"
				+ "WAEuODd6M5NHplKLqBdssK5EH9DGC6uU9sYxHqGTIeh3/RGg2uxRyH92CukajEgn\n"
				+ "OSDw7lWLZt9GhOw/CHrCc/UDhfhnT3V0N7DC1sIOkMVxg7Hf8jlxYkp03hTmMw7s\n"
				+ "4NKK5Bjnj2wyC/20SHnDw+WU7mW8aXygcsp3Rhpy4GADwHvXcJM4xv7t6tNvBEui\n"
				+ "ilvrB/ahAoGBAPLgv6LbNg31lMs3Dq1VboT2yUiW1rCESEhnmNAV3reuFLt15bRN\n"
				+ "N0oiD5bEAYViMHFvhXNrOtHP/xP9UIMXl9OZTrugE+65AAfYdp1M4VEv5Bqu6a9M\n"
				+ "GrL+M0k0phiOUlqpn1wiVqM8pLTNOqPo85dtVKVLIkahblipyvdupT5tAoGBANnX\n"
				+ "OUwOfUCjcK8dljwxFHPmPczZK5ckBNaTzHGx0dDBKjvqzz9r6vMYyIlJvdIT+EL7\n"
				+ "eSPokDhKP/l6wUVqc+pFppzrBP3juRVITgPmtGVclH/cMixBuy1XwaKo5qecndoJ\n"
				+ "yCBSGXEKES6Pg1X7/lVKOQlozxovdhvHCSZF6ZobAoGAeUNPSu9p2KRhquiNUmuS\n"
				+ "J57TtoNhI3aYZFYdDN+ueETZIxNlIZVf4oqI//xSyhbRGwHUPmEuV+0ibQePuDQC\n"
				+ "YOptTe5JpWoGouQnrLfi01c26z+jextjRTT3xDgeKap9YbjI0QZv/UZc8cx517aK\n"
				+ "UHOMzI5ryZn17xyvMsSyii0CgYBHuU9KNXMT9zxAzBMNGnPLfUFX0yFBEEDvjZZA\n"
				+ "0PVuMEuBktxN23BuPfi5CyiOpLiXBUlrg0UI45mQwNQl0Nj9h5VGETOBjJsB4N6e\n"
				+ "9jTrMsJKHuv+Gl5QnZZJwia/hReMFLBpw95Qk6n4lJP/mYqx9lA1Qub9jibrGmtu\n"
				+ "yJIThQKBgFffqhO7ZGWOmoMSKUyTemKJ8LwSPJTWKiOtxjK1g5wuVCoPWBj3WOhO\n"
				+ "zusqafhdJNFsI1cy0ZiRsRcegLK5VWehaPywj0zVf+tDqbb8teOayakn/4RQ1lIF\n"
				+ "BaDd01ooIX8Uuydf06TiZt4u11ikjPFv1TY6HFqMnb7USjp+Ge07\n" + "-----END RSA PRIVATE KEY-----\n";

		String rsaPublicKey = "-----BEGIN PUBLIC KEY-----\n"
				+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzqyzjjC6Mu679TyTrokg\n"
				+ "1ifH8SsqyLNhpyn/ToyxLahJPPtyDcC+QwRuIzhLR2JbrMNVbWd3LjfPlXLaqHL2\n"
				+ "3v9EOYSe8is+iKSsXW0CrsdiztNnY1ZczzUdN+4Ic7CQZxHYdI1IRumd5O1q0AjV\n"
				+ "OMpwPoZtvmvkqEnfhnoUOPo1hH5XY7rmTWEMg0JPZked2zljGKEIBt1gmRvwxuDw\n"
				+ "BKteycveUHDe7+fvH5TwdVoHEbNsHCRrO1RpmBd5TG1PrCXVB/wSiyBsxld7H6JY\n"
				+ "zE7ic8uGT98BLvZGE0qV9D0fR4z+XIow073ZOIa9v8aPu/2QIpbv6x0re5gPRTAn\n" + "fwIDAQAB\n"
				+ "-----END PUBLIC KEY-----";

		String pp = "{\n" + "  \"sub\": \"1234567890\",\n" + "  \"name\": \"John Doe\",\n" + "  \"iat\": 1516239022\n"
				+ "}";
		
	     String ecKey = "-----BEGIN EC PRIVATE KEY-----\n" +
	                "MIGkAgEBBDCDf1YDv40Afo7rhgMP7H2qEokTfn2HQqsxCTIw5aBvYeWL8WNPGj2J\n" +
	                "n4knhMcH/GOgBwYFK4EEACKhZANiAAQwReUQEcPxQ+8KTM4rPj3w62Q4ssMOLm8t\n" +
	                "B02Mp5MZEfoB5TfsFPJqnrHJ/mLVYgQPFY7T0OcHx7TtJgpLLMWmx0Lm+npGBa3u\n" +
	                "whwletgqqD+u0dWHnWkfnSdnDJN3zHY=\n" +
	                "-----END EC PRIVATE KEY-----";
	     
	     String serialized = "eyJraWQiOiJmYmM1MDY5Zi0zZmE0LTRkZmEtYjcxOS00MDhmNTM3ZGIzZjciLCJhbGciOiJFUzM4NCJ9.ewogICJzdWIiOiAiMTIzNDU2Nzg5MCIsCiAgIm5hbWUiOiAiSm9obiBEb2UiLAogICJpYXQiOiAxNTE2MjM5MDIyCn0.bNnI802tg1MsNAextW4qGyRq9d5z5-CTl5Dw93WEOLka0rVJ4ccB4_zFjqe9rBJsn18tFRgq1Mmy7BugqyJ6RzZbT6nMPuw-BFwXNRhLSNsv8n6uhKOy263urxIIVRi9";
		
	     //System.out.println(rsaPrivatekey);
	     
	     
	     String pubKey = "-----BEGIN PUBLIC KEY-----\n" +
	                "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAUv/w4x8pgm9U7J6CC/aRRG6JxJrj\n" +
	                "xCWUaQn4PcN36vO4Mqug6IlC8q/kZoG6KMzW/J0GssPLQTs/Cd3RXG6VUREBoYwe\n" +
	                "JZ0AOxbDAExxJj74lGcp3m84uK2Mue6yl/+ORNJgyDc1Rk8CxWHfQeajABqA1CQ0\n" +
	                "AWKRJt9SsNI5wK5nq0A=\n" +
	                "-----END PUBLIC KEY-----";
		
		
		//rsaVerifier(rsaPrivatekey,"PS384",pp);
		JWS jws  = new JWS();
		System.out.println(jws.deterMineObjectAndVerify(null, null, serialized, null, null, pubKey));
	//	System.out.println(jws.deterMineObjectAndSign(ecKey,"ES384",pp));
		String[] arr = new String[]{"HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"};
		//System.out.println(jws.generateKey("ES256",pp));
		//System.out.println(jws.generateKey("ES384",pp));
		//System.out.println(jws.generateKey("ES512",pp));
		for (int i = 0; i < arr.length; i++) {
		//	System.out.println(jws.generateKey("ES384",pp));
			break;
		}

	}
	
	public  boolean deterMineObjectAndVerify(final String sharedsecret,String singature, String serialzed, String algo,String payload, String publickey) throws Exception {
		
		JWSObject jwsObject = JWSObject.parse(serialzed);
		boolean isValid = false;
		if(sharedsecret!=null)
		{
			JWSVerifier verifier = new MACVerifier(sharedsecret);
			isValid = jwsObject.verify(verifier);
		}
		
		System.out.println(jwsObject.getPayload().toString());
		
		
		PemParser pem = new PemParser();
		Object obj = pem.parsePemFileObject(publickey);
		
		System.out.println(obj.getClass());
		
		
		return isValid;
		
	}
	
	

	public  jwspojo deterMineObjectAndSign(final String privateKey,String algo,String payload) throws Exception {
		// macVerifier();

		PemParser pem = new PemParser();
		Object obj = pem.parsePemFileObject(privateKey);
		
		//System.out.println(obj.getClass());

		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) {
			return RSASinger(payload,algo, obj);
		}

		if (obj instanceof org.bouncycastle.jce.provider.JCERSAPrivateKey) {
			return RSASinger(payload,algo, obj);

		}
		if (obj instanceof org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)
		{
			return ECSinger(payload,algo, obj);
		}
		
		return null;
	}
	
	public jwspojo sign(String algo, String payload,String sharedSecret) throws Exception
	{
		return sign(algo, payload, sharedSecret,null);
	}
	
	public jwspojo sign(String algo, String payload,String sharedSecret,String privatekey) throws Exception
	{
		
		jwspojo jwspojo = new jwspojo();
		
		if(algo.equalsIgnoreCase("HS256") || algo.equalsIgnoreCase("HS384") || algo.equalsIgnoreCase("HS512"))
		{
			JWSSigner signer = new MACSigner(sharedSecret.getBytes("UTF-8"));
			JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);
			JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlgorithm),new Payload(payload));
			// Apply the HMAC
			jwsObject.sign(signer);
			JWSHeader header = jwsObject.getHeader();
			
			jwspojo.setSerialize(jwsObject.serialize());
			jwspojo.setSignature(jwsObject.getSignature().toString());
			jwspojo.setState(jwsObject.getState().name());
			jwspojo.setHeader(header.toString());
			

		}
		
		if(algo.equalsIgnoreCase("RS256") || algo.equalsIgnoreCase("RS384") || algo.equalsIgnoreCase("RS512") 
				|| algo.equalsIgnoreCase("PS256") || algo.equalsIgnoreCase("PS384") 
				|| algo.equalsIgnoreCase("PS512")
				|| algo.equalsIgnoreCase("ES256")
				|| algo.equalsIgnoreCase("ES384")
				|| algo.equalsIgnoreCase("ES512"))
		{
			return deterMineObjectAndSign(privatekey, algo, payload);
		}
		
		
		
		return jwspojo;
		
	}
	
	public  jwspojo generateKey(String algo,String payload) throws Exception
	{
		jwspojo jwspojo = new jwspojo();
		if(algo.equalsIgnoreCase("HS256") || algo.equalsIgnoreCase("HS384") || algo.equalsIgnoreCase("HS512"))
		{
			SecureRandom random = new SecureRandom();
			byte[] sharedSecret = new byte[32];
			random.nextBytes(sharedSecret);
			if(algo.equals("HS384"))
			{
				sharedSecret = new byte[48];
				random.nextBytes(sharedSecret);
			}
			if(algo.equals("HS512"))
			{
				sharedSecret = new byte[64];
				random.nextBytes(sharedSecret);
			}
			
			JWSSigner signer = new MACSigner(sharedSecret);
			JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);
			JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlgorithm),new Payload(payload));
			// Apply the HMAC
			jwsObject.sign(signer);
			
			//System.out.println("1->" + jwsObject.serialize());
			//System.out.println("2->" + jwsObject.getSignature());
			//System.out.println("3->" + Utils.toBase64Encode(sharedSecret));
			
			JWSHeader header = jwsObject.getHeader();
			
			jwspojo.setSerialize(jwsObject.serialize());
			jwspojo.setSignature(jwsObject.getSignature().toString());
			jwspojo.setState(jwsObject.getState().name());
			jwspojo.setSharedSecret(Utils.toBase64Encode(sharedSecret));
			jwspojo.setHeader(header.toString());
			
			

			//System.out.println(jwspojo);
			
		}
		
		if(algo.equalsIgnoreCase("RS256") || algo.equalsIgnoreCase("RS384") || algo.equalsIgnoreCase("RS512") || algo.equalsIgnoreCase("PS256") || algo.equalsIgnoreCase("PS384") || algo.equalsIgnoreCase("PS512") )
		{
			JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);
			KeyPair kp = Utils.generateRSAKeyPair("RSA", 2048);
			//System.out.println(Utils.toPem(kp));
			RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)kp.getPublic()).privateKey(kp.getPrivate()).keyUse(KeyUse.SIGNATURE)
					.algorithm(new Algorithm(algo)).keyID(UUID.randomUUID().toString()).build();
			JWSSigner signer = new RSASSASigner(rsaJWK);
			JWSObject jwsObject = new JWSObject(
					new JWSHeader.Builder(jwsAlgorithm).keyID(rsaJWK.getKeyID()).build(), new Payload(payload));
			jwsObject.sign(signer);
			JWSHeader header = jwsObject.getHeader();
			
			jwspojo.setSerialize(jwsObject.serialize());
			jwspojo.setSignature(jwsObject.getSignature().toString());
			jwspojo.setState(jwsObject.getState().name());
			jwspojo.setPrivateKey(Utils.toPem(kp));
			jwspojo.setPublicKey(Utils.toPem(kp.getPublic()));
			jwspojo.setHeader(header.toString());

			//System.out.println(jwspojo);
		}
		
		if(algo.equalsIgnoreCase("ES256") || algo.equalsIgnoreCase("ES384") || algo.equalsIgnoreCase("ES512") ) 
		{
			
			String curvename="secp256r1";
			Curve curve =Curve.P_256;
			if(algo.equalsIgnoreCase("ES384"))
			{
				curvename="secp384r1";
				curve =Curve.P_384;
			}
			if(algo.equalsIgnoreCase("ES512"))
			{
				curvename="secp521r1";
				curve =Curve.P_521;
			}
			
			
			JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);
			//Curve curve = new Curve(algo);
			KeyPair kp =  Utils.generateKeyPairECDSA(curvename);
			//System.out.println("Algo " + algo);
			//System.out.println(Utils.toPem(kp));
			//System.out.println(Utils.toPem(kp.getPublic()));
			ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
			
			ECKey ecKey = new ECKey.Builder(curve, publicKey).privateKey(kp.getPrivate()).keyUse(KeyUse.SIGNATURE)
					.algorithm(new Algorithm(algo)).keyID(UUID.randomUUID().toString()).build();
			
			JWSSigner signer = new ECDSASigner(ecKey);
			
			JWSObject jwsObject = new JWSObject(
					new JWSHeader.Builder(jwsAlgorithm).keyID(ecKey.getKeyID()).build(), new Payload(payload));
			jwsObject.sign(signer);
			JWSHeader header = jwsObject.getHeader();
			
			jwspojo.setSerialize(jwsObject.serialize());
			jwspojo.setSignature(jwsObject.getSignature().toString());
			jwspojo.setState(jwsObject.getState().name());
			jwspojo.setPrivateKey(Utils.toPem(kp));
			jwspojo.setPublicKey(Utils.toPem(kp.getPublic()));
			jwspojo.setHeader(header.toString());

			//System.out.println(jwspojo);
			
			
			
		}
	
		return jwspojo;
		
		
	}
	
	private jwspojo ECSinger(String pp,String algo, Object obj) throws Exception
	{
		jwspojo jwspojo = new jwspojo();
		PublicKey publickey;
		BCECPrivateKey  privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)obj;
		ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) privateCrtKey.getParams();
		
		//System.out.println(ecNamedCurveSpec.getName());
		
		String curvename="secp256r1";
		Curve curve =null;
		
		if("secp256r1".equalsIgnoreCase(ecNamedCurveSpec.getName()))
		{
			curve =Curve.P_256;
		}
		
		
		if("secp384r1".equalsIgnoreCase(ecNamedCurveSpec.getName()))
		{
			curvename="secp384r1";
			curve =Curve.P_384;
		}
		if("secp521r1".equalsIgnoreCase(ecNamedCurveSpec.getName()))
		{
			curvename="secp521r1";
			curve =Curve.P_521;
		}
		
		if(curve==null)
		{
			throw new Exception("The EC Private Key curve name is "+ ecNamedCurveSpec.getName() + " JWS Supported curve is secp256r1,secp384r1,secp521r1 ");
		}
		
		//Curve curve = new Curve(ecNamedCurveSpec.getName());
		
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecNamedCurveSpec.getGenerator(),ecNamedCurveSpec);
		
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		
		publickey = keyFactory.generatePublic(publicKeySpec);
		
		//System.out.println(Utils.toPem(publickey));
		
		ECPublicKey  pub1 = (ECPublicKey)publickey;
		
		ECKey ecJWK = new ECKey.Builder(curve, pub1).privateKey(privateCrtKey).keyUse(KeyUse.SIGNATURE)
				.algorithm(new Algorithm(algo)).keyID(UUID.randomUUID().toString()).build();
		JWSSigner signer = new ECDSASigner(ecJWK);
		JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);
		JWSObject jwsObject = new JWSObject(
				new JWSHeader.Builder(jwsAlgorithm).keyID(ecJWK.getKeyID()).build(), new Payload(pp));
		// Compute the EC signature
		jwsObject.sign(signer);
		
		
		JWSHeader header = jwsObject.getHeader();
		
		jwspojo.setSerialize(jwsObject.serialize());
		jwspojo.setSignature(jwsObject.getSignature().toString());
		jwspojo.setState(jwsObject.getState().name());
		//jwspojo.setPrivateKey(Utils.toPem(kp));
		//jwspojo.setPublicKey(Utils.toPem(kp.getPublic()));
		jwspojo.setHeader(header.toString());
		
		return jwspojo;
		
		
	}

	private  jwspojo RSASinger(String pp,String algo, Object obj)
			throws Exception {
		PublicKey publickey;
		BCRSAPrivateCrtKey privateCrtKey = (org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey) obj;
		//System.out.println("Her2---");

		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateCrtKey.getModulus(),
				privateCrtKey.getPublicExponent());

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publickey = keyFactory.generatePublic(publicKeySpec);

		//System.out.println(Utils.toPem(publickey));
		//System.out.println(Utils.toPem(privateCrtKey));

		RSAPublicKey pub1 = (RSAPublicKey) publickey;

		RSAKey rsaJWK = new RSAKey.Builder(pub1).privateKey(privateCrtKey).keyUse(KeyUse.SIGNATURE)
				.algorithm(new Algorithm(algo)).keyID(UUID.randomUUID().toString()).build();

		JWSSigner signer = new RSASSASigner(rsaJWK);
		
		JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(algo);

		JWSObject jwsObject = new JWSObject(
				new JWSHeader.Builder(jwsAlgorithm).keyID(rsaJWK.getKeyID()).build(), new Payload(pp));

		// Compute the RSA signature
		jwsObject.sign(signer);

		String s = jwsObject.serialize();

		//System.out.println("--> " + s);

		// To parse the JWS and verify it, e.g. on client-side
		jwsObject = JWSObject.parse(s);

		//System.out.println("<---" + jwsObject.getParsedString());
		
		JWSHeader header = jwsObject.getHeader();
		
		//System.out.println(header);
		
		Payload paylod=jwsObject.getPayload();
		
		//System.out.println(paylod);
		
		State state = jwsObject.getState();
		
		//System.out.println(state);
		
//		Base64URL[] base54 = jwsObject.getParsedParts();
//		for (int i = 0; i < base54.length; i++) {
//			Base64URL base = base54[i];
//			System.out.println(base.toJSONString());
//		}
		
		jwspojo jwspojo = new jwspojo();
		
		jwspojo.setSerialize(jwsObject.serialize());
		jwspojo.setSignature(jwsObject.getSignature().toString());
		jwspojo.setState(jwsObject.getState().name());
		//jwspojo.setPrivateKey(Utils.toPem(kp));
		//jwspojo.setPublicKey(Utils.toPem(kp.getPublic()));
		jwspojo.setHeader(header.toString());
		
		return jwspojo;
		

		//JWSVerifier verifier = new RSASSAVerifier(pub1);

		//System.out.println(jwsObject.verify(verifier));
	}

	private static RSAKey make(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keySize);
			KeyPair kp = generator.generateKeyPair();

			RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
			RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

			return new RSAKey.Builder(pub).privateKey(priv).keyUse(keyUse).algorithm(keyAlg).keyID(kid).build();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void macVerifier() throws KeyLengthException, JOSEException, ParseException {
		SecureRandom random = new SecureRandom();
		byte[] sharedSecret = new byte[64];
		random.nextBytes(sharedSecret);

		String pp = "{\n" + "  \"sub\": \"1234567890\",\n" + "  \"name\": \"John Doe\",\n" + "  \"iat\": 1516239022\n"
				+ "}";

		System.out.println(Utils.toBase64Encode(sharedSecret));

		// Create HMAC signer
		JWSSigner signer = new MACSigner(sharedSecret);

		// Prepare JWS object with "Hello, world!" payload
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS512), new Payload(pp));

		// Apply the HMAC
		jwsObject.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String s = jwsObject.serialize();

		System.out.println(s);

		// To parse the JWS and verify it, e.g. on client-side
		jwsObject = JWSObject.parse(s);

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		System.out.println(jwsObject.verify(verifier));

		System.out.println(jwsObject.getPayload().toString());
	}

}
