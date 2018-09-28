package jwk;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import cacerts.Utils;
import pem.PemParser;
import pojo.jwkpojo;
import rsa.RSAUtil;


public class JwkKeyGenerator {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public String convertPEMtoJWK(String input) throws Exception
	{
		
		if(null==input || input.length()==0)
		{
			throw new Exception("Input is Null or Empty ");
		}
		
		try {

			byte[] content = input.getBytes();
			InputStream is = new ByteArrayInputStream(content);
			InputStreamReader isr = new InputStreamReader(is);

			Reader br = new BufferedReader(isr);
			PEMParser parser = new PEMParser(br);

			Object obj = parser.readObject();
			System.out.println(obj.getClass());

		
			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
				SubjectPublicKeyInfo subjectPublicKeyInfo = pemKeyPair.getPublicKeyInfo();
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				
				KeyPair keyPair =  new KeyPair(publickey, privateKey);
				
				if(input.contains("BEGIN EC PRIVATE KEY"))
				{
					JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
						    .privateKey((ECPrivateKey) keyPair.getPrivate())
						    .build();
					
					return jwk.toJSONString();
				}
				
				else {
				
					JWK jwk;
					try {
						jwk = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
							    .privateKey((RSAPrivateKey)keyPair.getPrivate())
							    .keyID(UUID.randomUUID().toString())
							    .build();
						return jwk.toJSONString();
					} catch (Exception e) {
						
					}
				}
			}
			
			if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) obj;
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PublicKey publickey = jcaPEMKeyConverter.getPublicKey(subjectPublicKeyInfo);
				
				JWK jwk = new RSAKey.Builder((RSAPublicKey)publickey)
					    .keyID(UUID.randomUUID().toString())
					    .build();
				return jwk.toJSONString();
				
			}
			
			if(obj instanceof org.bouncycastle.cert.X509CertificateHolder)
			{
				X509CertificateHolder x509CertificateHolder = (org.bouncycastle.cert.X509CertificateHolder)obj;
				JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter().setProvider("BC");
				X509Certificate x509Certificate =  jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
				PublicKey publicKey = x509Certificate.getPublicKey();
				JWK jwk = new RSAKey.Builder((RSAPublicKey)publicKey)
					    .keyID(UUID.randomUUID().toString())
					    .build();
				return jwk.toJSONString();
			}
			
			if (obj instanceof java.security.KeyPair) {
				KeyPair keyPair = (KeyPair) obj;
				JWK jwk = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
					    .privateKey((RSAPrivateKey)keyPair.getPrivate())
					    .keyID(UUID.randomUUID().toString())
					    .build();
				return jwk.toJSONString();
			}
			
			
			}catch (Exception e) {
				throw new Exception ("Failed to generate JWK key format" , e);
			}
		return null;
		
		
	}
	
	public jwkpojo convertJWKtoPEM(String input,String kty) throws Exception
	
	{
		jwkpojo jwkpojo =  new jwkpojo();
		if(null==input || input.length()==0)
		{
			throw new Exception("Input is Null or Empty ");
		}
		
		boolean flag=false;
		
		if("rsa".equalsIgnoreCase(kty))
		{
		
		try {
			RSAKey jwk = (RSAKey)JWK.parse(input);
			
			java.security.KeyPair kp2 = (java.security.KeyPair)jwk.toKeyPair();
			if(kp2!=null)
			{
				
				try {
					jwkpojo.setPrivateKey(Utils.toPem(kp2));
				} catch (Exception e) {
					// There is chances only public Key Submited
				}
			}
			
			PublicKey pk = jwk.toPublicKey();
			if(pk!=null)
			{
				try {
					jwkpojo.setPublicKey(Utils.toPem(pk));
				} catch (Exception e) {
					// There is chances only Private Key Submited
				}
			}
			
			return jwkpojo;
			
		} catch (Exception e) {
			// IGNORE This may be EC Try it
			
			
		}
		
		}else {
		

			try {
				ECKey ecKey = (ECKey)JWK.parse(input);
				jwkpojo.setPrivateKey(Utils.toPem(ecKey.toKeyPair()));
				jwkpojo.setPublicKey(Utils.toPem(ecKey.toPublicKey()));
				return jwkpojo;
			} catch (Exception e) {
				throw new Exception ("Provided Input not recognized as Valid JWK for RSA and EC");
			}

		}
		return jwkpojo;
	}
	
	public String generateRSAJWKKey(int keySize, String keyUsage) throws Exception
	{
		
		RSAKey jwk =null;
		if(keyUsage!=null && keyUsage.equalsIgnoreCase("encryption"))
		{
			 jwk = new RSAKeyGenerator(keySize)
				    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
				    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
				    .generate();
		}
		
		else {
			
			jwk = new RSAKeyGenerator(keySize)
				    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
				    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
				    .generate();

		}
		
		
		if(jwk!=null)
		{
			return jwk.toJSONString();
		}
		
		return null;
		
		
	}
	
	public String generateECJWKKey(String curveName) throws Exception
	{
		
		ECKey jwk =null;
		
		
		
		if(curveName==null )
		{
			 jwk = new ECKeyGenerator(Curve.P_256)
				    .generate();
			 return jwk.toJSONString();
		}
		else {
			
			if("P-256".equalsIgnoreCase(curveName))
			{
				jwk = new ECKeyGenerator(Curve.P_256)
					    .generate();
				 return jwk.toJSONString();
			}
			
			if("P-256K".equalsIgnoreCase(curveName))
			{
				jwk = new ECKeyGenerator(Curve.P_256K)
					    .generate();
				 return jwk.toJSONString();
			}
			

			if("P-384".equalsIgnoreCase(curveName))
			{
				jwk = new ECKeyGenerator(Curve.P_384)
					    .generate();
				 return jwk.toJSONString();
			}
			
			
			if("P-521".equalsIgnoreCase(curveName))
			{
				jwk = new ECKeyGenerator(Curve.P_521)
					    .generate();
				 return jwk.toJSONString();
			}
			
			
		}
		
		
		return null;
		
		
	}
	
	public String generateOctetKey(String curveName) throws Exception
	{
		OctetKeyPair jwk=null;
		
		if("Ed25519".equalsIgnoreCase(curveName))
		{
			jwk = new OctetKeyPairGenerator(Curve.Ed25519)
			    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
			    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
			    .generate();
		return jwk.toJSONString();
		}
		
		if("Ed448".equalsIgnoreCase(curveName))
		{
			jwk = new OctetKeyPairGenerator(Curve.Ed448)
			    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
			    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
			    .generate();
		return jwk.toJSONString();
		}
		
		if("X25519".equalsIgnoreCase(curveName))
		{
			jwk = new OctetKeyPairGenerator(Curve.X25519)
			    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
			    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
			    .generate();
		return jwk.toJSONString();
		}
		
		if("X448".equalsIgnoreCase(curveName))
		{
			jwk = new OctetKeyPairGenerator(Curve.X448)
			    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
			    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
			    .generate();
		return jwk.toJSONString();
		}
		
		return null;
		
	}
	
	public String generateOctetSequenceKey(String algoName ) throws Exception
	{
		OctetSequenceKey jwk = null;
		if("HS256".equalsIgnoreCase(algoName))
		{
		 jwk = new OctetSequenceKeyGenerator(256)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(JWSAlgorithm.HS256) // indicate the intended key alg (optional)
			    .generate();
		 return jwk.toJSONString();
		}
		
		if("HS384".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(384)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(JWSAlgorithm.HS384) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		if("HS512".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(512)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(JWSAlgorithm.HS512) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		if("A128GCM".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(128)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(EncryptionMethod.A128GCM) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		if("A192GCM".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(192)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(EncryptionMethod.A192GCM) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		if("A256GCM".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(256)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(EncryptionMethod.A256GCM) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		if("A128CBC_HS256".equalsIgnoreCase(algoName))
		{
			jwk= new OctetSequenceKeyGenerator(128)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(EncryptionMethod.A128CBC_HS256) // indicate the intended key alg (optional)
			    .generate();
			return jwk.toJSONString();
		}
		
		return null;
		
	}
	
	public String generateOctetSequenceKeywithHmac(String algoName ) throws Exception
	{
		JWK jwk = null;
		SecretKey hmacKey = null;
		if("HS256".equalsIgnoreCase(algoName))
		{
		hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
		jwk = new OctetSequenceKey.Builder(hmacKey)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(JWSAlgorithm.HS256) // indicate the intended key alg (optional)
			    .build();
		 return jwk.toJSONString();
		}
		
		if("HS384".equalsIgnoreCase(algoName))
		{
			hmacKey = KeyGenerator.getInstance("HmacSha384").generateKey();
			jwk = new OctetSequenceKey.Builder(hmacKey)
				    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
				    .algorithm(JWSAlgorithm.HS384) // indicate the intended key alg (optional)
				    .build();
		}
		
		if("HS512".equalsIgnoreCase(algoName))
		{
			hmacKey = KeyGenerator.getInstance("HmacSha512").generateKey();
			jwk = new OctetSequenceKey.Builder(hmacKey)
				    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
				    .algorithm(JWSAlgorithm.HS512) // indicate the intended key alg (optional)
				    .build();
		}
		
		return null;
		
	}
	
	
	
	public static void main(String[] args) throws Exception{
		
		JwkKeyGenerator generator = new JwkKeyGenerator();
		
		jwkpojo jwkpojo =  new jwkpojo();
		
		System.out.println();
		
		String p2="{\"alg\":\"RSA-OAEP-256\",\"e\":\"AQAB\",\"ext\":true,\"key_ops\":[\"encrypt\"],\"kty\":\"RSA\",\"n\":\"0c9eRO2uCJ67AnY4WAh_FfY85M4JaePlF24Poiohn-kVsD7ZkN5YLpiH6MhBMojyX28p-piZSNpTZhLBHun6hxjL6hqbqsuxUgSoLdfg6ThxqmZwOwxKdjMiQvDf2D3bir_p0dkQTnM-4QkK1u2h1BnVUo1a_hWQcPrNUMa0ox6_u4hInddm-jf6tO9KiUG_7iStU3AgSwj1drnvBP8KM1WpDm6VaKNLKILZWtpWQIQbboLjV2ldrmcc7dk7NCnmIwSFXYQQ9_fZZ3GLu9JNUmHmUvju19ZVzncSIrCvQfMYZTP1Oppu_xvNb7EO-ujxhM3SxWuophwLsXMpQXK5qQ\"}";
		
		String pk ="{\"alg\":\"RSA-OAEP-256\",\"d\":\"CC4FaFli61b0seO-WhnjfFDRAERg4pGqOp-ao6yUY5lGVjLIujGucCo-cWOBAg-H0ds9bc9A-G_tIrrOL5cc2viEXYmYA25k_2wm7JYA783_WCfuWYUh9J28wXFdW20GulTW2B2DTCkbK4w7LXHIP6wiAjLoxBACpcSz_EJlFSJLnA4bJeYTIr4ww6TUxtjoM4lIV6FWHiBVSHD_N4dcjvA4UIe7Z9BDdnaDlpzibT4eCBF5ZT6Fto_wt0YNzHJjQpdeGro3k6ixRxZzsWr1q85t6YBTqPksjwuIHyaEwkfj_q-0M1VXJ_3m-dqCDTqEnOBmZAo4n0TU5eq_O30kIQ\",\"dp\":\"zsPprvKGau5ZJTykv0GMm4Wu_ZDEsvtBZAWV1D0izzjVMBZAh8X8uHwVUkM82hwsMJt1-jVwA60_vY5VxeHlXzX1RkA2iUvJJdXRhftm-xd-hNb1w5fC5cMcW55Krat3IqgntmuV6o4dW76WfDzIZ1xn0LYmAlOH-2KfOUIQsbE\",\"dq\":\"VgMgs3wNn8drLk-AQhOVEQ8o0QWfd2I7IATtTvSbLXQcL3-Lwr6UKgsanlvPfM32L9zPL9v0iWYmMLsto3D77V6_b17V5S03kn7f5bKBXeH9KS3N_cl4PUsI_zMKksndKmsWvsNqX5N3ILtocjY9PcEe2RNWzNJlJuyv0lQkhnE\",\"e\":\"AQAB\",\"ext\":true,\"key_ops\":[\"decrypt\"],\"kty\":\"RSA\",\"n\":\"tq5aUtuwU-l-383Fn8wlAbo8uZahNheJYaX-R43l7m-SYhDq7hu1qOihLw9un5r3yi3pfzWAWAOgccDVEd3BG9FbYvfN1x72mx9OGUrwf5-dbzV6N1naYOUIQnxiTIqMIq7XIAD-4YunP6zWk8cYEuBvhOZkfulsdhBKwnybEXGN7tFY1jXtjcqx3UvnWWoxSpdRLg-G7xF2BdGBRN2MX6kqZfDIf3onOVBmepyxrlo4UynPdui_NMEO7Mx67F2MJiFtyCbzFRKBgZYD93qnHtrOrhPVYKvB5t59iaAUU9DWOlooJ-4nxB3ngKxCXB4RcemK4G4hFGAk4Xu1jXdZcQ\",\"p\":\"6K3l5ttxLfTjSzygTdCheDdlxqkkGwrgca_z4DARWyPYRDO7YeMPfiKlgHAI_ag8VK2kyWAym9yIUN-Zr3NiowbeSRTiH9FhbQTb3_NBrLzZRl1uFvhagaqAykBmLL2Z7BxIrpQn8MFysYSYNgeHQg3ej993PcjjKvm-PS1PrSk\",\"q\":\"yP2YxPxzQ920zV1mxp7tLygWo4VAwyH11Xbyuh3Gu3rSOrU8bdkIRoiPELCMuIFsgqpRNSJzwO7H9oT_Dm1997x_aGOBV4cwwidYPDFa3L4IiTyxVRXC1QBLc_qcy_5R7yuo-T8xhMEPiZR8C0558rs8dvlolqg561CWaw0diwk\",\"qi\":\"QyNEPYUiMvegu1TL5KLizohDmkjxCOLaaWrkXjgiICf7EFTnpGguIPqFCTVwq5zEK04Ze-raG81D0-c96Ab74oYh4hfXe_64BdRevggwuE4KK1ycqiO49w5U0m5Gz8-VsOIVBZRpfjpioVtbFJ289f2UJab-TgKHkVxhlLNetus\"}";
		
		jwkpojo = generator.convertJWKtoPEM(pk,"rsa");
		
		
		System.out.println(generator.convertPEMtoJWK(jwkpojo.getPrivateKey()));
		System.out.println(generator.convertPEMtoJWK(jwkpojo.getPublicKey()));
		
		
		jwkpojo = generator.convertJWKtoPEM(generator.generateECJWKKey("P-256"),"ec");
		
		//System.out.println(jwkpojo.getPrivateKey());

		
		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("ec.pem"));
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

		try {
			System.out.println("everything " + everything);
			System.out.println("everything--" +generator.convertPEMtoJWK(everything));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        


        
        //System.out.println(generator.convertPEMtoJWK(generator.generateECJWKKey("P-256")));
		
		
		String ki="{\"p\":\"2zqsrEZEolzTZyJYersWtcOdkEYGUshHIWDaYBf_eLpF6UlTvHUMO0HP8p8q5IwEQGp5xgMvlkvCXOnOVdPOBYHACXQro878eiVGa8aKQ7Rkij7bQvD5wcSbvI_s4exTz4qyv6ksvyud1_cxSGvq4YBukUMq1G8rrPIWs0FB3r8\",\"kty\":\"RSA\",\"q\":\"zpi32LHZclMtTx5nkVOa9VPhY3qdTHtYjM55jhipyzCMHGQHot-Yqwqw8gmhMGBoCHHCFrNNSenZif0cV2nEl3zdZtDn5n-T0Xi-r_M6KvLft7KgcIPfit0vQYri4frivfd33erzF0np5fD8Xd0CZKxS2Wo5Theo9lioI0gdp5s\",\"d\":\"fczRBiexE3CQ-ODiFBA4EyLtznN9BxQKA7xP481tetEm-9JfBNun89jbqYJLCAUI88jqBWdCLlB8fruwlZAF2iabUBoRWE68znrSbTETKkZPTnExYZx88_GBHXWEcv3LkhWgy8fOcYD7AsKjvA-GHx_jUoclT-Uq08frCBzbzh90tRisdauEalCltuHOkpcJgCDXrLTpCAVZXITexKlRIsM0TQ7PmGH3fhgmL7KhVkqhFwsu7YXeA7xEaQnMPM2wZeMK2bBF85hUhlRl8s6n961MNWzhUzv3RCE5b5FSrSnxXDSzalyWWRtzCKDXe_QM1T_7BpH9nzLUJvDzDhSKYQ\",\"e\":\"AQAB\",\"use\":\"enc\",\"kid\":\"109f607c-f652-4e0a-ad0d-1e51522544fe\",\"qi\":\"W9nbcuZwr_dAipAgFzXWrra6IlF7C87b-buwp_htD6z44H5mvqU4WkzmUE_oEC1mREZg4Mu3grXLMFQt1QLIt8u_oZ_WRKFaPF8S0CmazE-GEXbMsdLVhQdZ_F_W2FgZ4w0n_X7JACn3D9k5q79kBPtcijL7kS1Q4riEN-J4oZE\",\"dp\":\"f9O9fRHX0Sf46AjhuGZAPqmZxNbftwMqXm7_xcoYXweV3gmwdpF1GVQtcRWXx_1QOVMcP_X5mFQCN3Top6jBVvqpw5lmHLSDCKGVZyAz3Hhhqy4tYOHrby05dYAiKjVHRRtlUFXPToSbG6L5rHWoVeYyEics4QMVX1klHU4unzc\",\"dq\":\"Gfwla5D7C6Egmsn1NtcwL1ksiSmb7Um6WoOB0HiTqqXhiZSfTUIYXrMKjHbfmkkV7LH6Ooa02u4Z2XxHe0snWfJvmoX-FQTI39jzCwhpsYs4zk8eVOiRTlMBpZnFbazzpfchUX1CtBQs4ioMY_XvXiA6j3QH3yWkr8943m8so68\",\"n\":\"sOv_OaoTkwRJiKVk-hRe8nr5G5AVEMAPmbj_x-gv3Htq0noPgnQuq6rTOr927_WLrD6SE1gojRbeYAdKrOWPz7mf4KZ8H6Sz_203jQzKfTelwYIK6iVZLILoCtkHNdlnwwGN1FzJmVVI7l0eXHxMYAQ7hQBwSHwU4XiLUSDZ3n3gnE-QhMCoYvHmxP0T3EWfFtl8J7k7e_TytfnxJJ6pX3CKDS6Gyr4Jlv6FgpEFSG3RxOBwKfeC9aHsd_sZNtvyq3u77mITAgo1jDnTeE8xYUkc_2B9ccHutu9TGwCl90eYv8WIK6inPumBi0rgPD7CSuL-sBl9SW_h4mVTbtN2pQ\"}\n";
		
		RSAKey jwk = (RSAKey)JWK.parse(ki);
		
		System.out.println(Utils.toPem(jwk.toKeyPair()));
		System.out.println(Utils.toPem(jwk.toPublicKey()));
		
		System.out.println(jwk.getClass());
		
		ECKey ecKey = (ECKey)JWK.parse(generator.generateECJWKKey("P-256"));
		
		ecKey.toPrivateKey();
		
		System.out.println(Utils.toPem(ecKey.toKeyPair()));
		System.out.println(Utils.toPem(ecKey.toPrivateKey())  + "Here--\n"+  Utils.toPem(ecKey.toPrivateKey()));
		System.out.println(Utils.toPem(ecKey.toPublicKey()));
		
		Reader rdr = new StringReader(Utils.toPem(ecKey.toPrivateKey()));
		Object parsed  =  new org.bouncycastle.openssl.PEMParser(rdr).readObject();
		
		KeyPair pair = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair)parsed);
		
		JWK jwk1 = new ECKey.Builder(Curve.P_256, (ECPublicKey) pair.getPublic())
			    .privateKey((ECPrivateKey) pair.getPrivate())
			    .build();
		
		System.exit(1);
		
		//System.out.println(generator.generateRSAJWKKey(1024, "encryption"));
		System.out.println(generator.generateRSAJWKKey(2048, "encryption"));
		System.out.println(generator.generateRSAJWKKey(4096, "encryption"));
		
		//System.out.println(generator.generateRSAJWKKey(1024, "signature"));
		System.out.println(generator.generateRSAJWKKey(2048, "signature"));
		System.out.println(generator.generateRSAJWKKey(4096, "signature"));
		
		System.out.println(generator.generateECJWKKey("P-256"));
		System.out.println(generator.generateECJWKKey("P-384"));
		System.out.println(generator.generateECJWKKey("P-521"));
		
		
		System.out.println(generator.generateOctetKey("Ed25519"));
		//System.out.println(generator.generateOctetKey("Ed448"));
		System.out.println(generator.generateOctetKey("X25519"));
		//System.out.println(generator.generateOctetKey("X448"));
		
		
		System.out.println(generator.generateOctetSequenceKey("HS256"));
		System.out.println(generator.generateOctetSequenceKey("HS384"));
		System.out.println(generator.generateOctetSequenceKey("HS512"));
		
		System.out.println(generator.generateOctetSequenceKey("A128GCM"));
		System.out.println(generator.generateOctetSequenceKey("A192GCM"));
		System.out.println(generator.generateOctetSequenceKey("A256GCM"));
		System.out.println(generator.generateOctetSequenceKey("A128CBC_HS256"));
		
		
		System.out.println(generator.generateOctetSequenceKeywithHmac("HS256"));
		//System.out.println(generator.generateOctetSequenceKeywithHmac("HS384"));
		//System.out.println(generator.generateOctetSequenceKeywithHmac("HS512"));
		
		
		
		
		System.out.println(Utils.toPem(jwk.toKeyPair()));
		System.out.println(Utils.toPem(jwk.toPublicKey()));
		
		System.out.println(jwk.getClass());
		
		
		
		ecKey.toPrivateKey();
		
		System.out.println(Utils.toPem(ecKey.toKeyPair()));
		System.out.println(Utils.toPem(ecKey.toPrivateKey()));
		System.out.println(Utils.toPem(ecKey.toPublicKey()));
		
		OctetSequenceKey osk = (OctetSequenceKey)JWK.parse(generator.generateOctetSequenceKey("HS256"));
		
		
		
		System.out.println(JWK.parse(generator.generateOctetSequenceKey("HS256")).getClass());
		
		System.out.println(JWK.parse(generator.generateOctetKey("Ed25519")).getClass());
		
		
		
	}

}
