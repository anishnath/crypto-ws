package jwk;

import java.security.Security;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;


public class JwkKeyGenerator {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
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
		
		
		
		
		
	}

}
