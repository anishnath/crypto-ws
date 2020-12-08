package fernet;

import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.StringValidator;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

import pojo.fernetpojo;

/**
 * 
 * @author anishnath
 *
 */

public class FernetEncryption {
	
	
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	static final Validator<String> validator = new StringValidator() {
		public TemporalAmount getTimeToLive() {
	        return Duration.ofSeconds(Instant.MAX.getEpochSecond());
	    }
    };
    
    public String generateKey()
    {
    	Key key = Key.generateKey();
    	return key.serialise();
    }
	
	public fernetpojo encrypt(String key1, String msg) throws Exception
	{
		Key key;
		try {
			key = new Key(key1);
		} catch (Exception e) {
			throw new Exception("Inavlid Fernet Keys");
		}
		final Token token = Token.generate(key, msg);		
		fernetpojo fernetpojo = new fernetpojo();
		fernetpojo.setIv(Base64.getUrlEncoder().encodeToString((token.getInitializationVector().getIV())));
		//fernetpojo.setToString(token.toString());
		fernetpojo.setTimestapmp(String.valueOf(token.getTimestamp()));
		fernetpojo.setSerialize(token.serialise());
		
		
		String encryptedString = token.toString();
		fernetpojo.setHmac((encryptedString.substring(encryptedString.indexOf("hmac=")+5,encryptedString.length()-1)));
		fernetpojo.setVersion(String.valueOf(token.getVersion() & 0xFF));
		
		
		//System.out.println(fernetpojo);
		return fernetpojo;
	}
	
	public String dcrypt(String key1, String fToken) throws Exception
	{
		
		Key key;
		try {
			key = new Key(key1);
		} catch (Exception e) {
			throw new Exception("Inavlid Fernet Keys");
		}
		Token token  = Token.fromString(fToken);
		String decrypttoken = token.validateAndDecrypt(key, validator);
		
		return decrypttoken;
		
	}
	
	public static void main(String[] args) throws Exception {
		
		final Key key = Key.generateKey();
		System.out.println(key.serialise());
		final Token token = Token.generate(key, "secret message");
		System.out.println(token.serialise());
		
		FernetEncryption encryption = new FernetEncryption();
		
		String msg = "secret message";
		String userkeykey = token.serialise();
		
		//System.out.println(userkeykey.length());
		
		userkeykey = "IcDaCAb1aHcIXYWEYkY9MsFSKtjguelUY0TYE0MGesU=";
		
		//System.out.println(encryption.encrypt(userkeykey, msg));
		
		fernetpojo fernetpojo = encryption.encrypt(userkeykey, msg);
		String decryptString = encryption.dcrypt(userkeykey, fernetpojo.getSerialize());
		System.out.println(decryptString);
		
		userkeykey = encryption.generateKey();
		fernetpojo = encryption.encrypt(userkeykey, msg);
		decryptString = encryption.dcrypt(userkeykey, fernetpojo.getSerialize());
		System.out.println(decryptString);
		
		

		
	}

	public static String 
    convertByteToString(byte byteValue) 
    { 
  
        // Convert byte value to String value 
        // using + operator method 
        String stringValue = "" + byteValue; 
  
        return (stringValue); 
    } 
}
