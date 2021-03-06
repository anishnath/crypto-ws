package rsa;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.*;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.PEMWriter;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * 
 * @author Anish Nath 
 * For Demo Visit https://8gwifi.org
 *
 */

public class RSAUtil {
	
	 static {
	        Security.addProvider(new BouncyCastleProvider());
	    }

	    protected static final String ALGORITHM = "RSA";

	    public RSAUtil()
	    {

	    }

	    public static String toPem(KeyPair keyPair) throws IOException {
	        StringWriter writer = new StringWriter();
	        PEMWriter pemWriter = new PEMWriter(writer);
	        try {
	            pemWriter.writeObject(keyPair);
	            pemWriter.flush();
	            return writer.toString();
	        } finally {
	            pemWriter.close();
	        }
	    }


	    public static String toPem(PublicKey keyPair) throws IOException {
	        StringWriter writer = new StringWriter();
	        PEMWriter pemWriter = new PEMWriter(writer);
	        try {
	            pemWriter.writeObject(keyPair);
	            pemWriter.flush();
	            return writer.toString();
	        } finally {
	            pemWriter.close();
	        }
	    }


	    public static KeyPair generateKey(int size ) throws NoSuchAlgorithmException
	    {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
	        keyGen.initialize(size);
	        KeyPair key = keyGen.generateKeyPair();
	        return key;
	    }


	    public static byte[] encrypt(byte[] text, PublicKey key, String cipherAlgo) throws Exception
	    {
	        byte[] cipherText = null;

	        Cipher cipher = Cipher.getInstance(cipherAlgo);

	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        cipherText = cipher.doFinal(text);
	        return cipherText;
	    }

	    public static byte[] encrypt(byte[] text, PrivateKey key, String cipherAlgo) throws Exception
	    {
	        byte[] cipherText = null;

	        Cipher cipher = Cipher.getInstance(cipherAlgo);

	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        cipherText = cipher.doFinal(text);
	        return cipherText;
	    }


	    public static String encrypt(String text, PublicKey key,String cipherAlgo) throws Exception
	    {
	        String encryptedText;
	        byte[] cipherText = encrypt(text.getBytes("UTF8"),key,cipherAlgo);
	        encryptedText = encodeBASE64(cipherText);
	        return encryptedText;
	    }

	    public static String encrypt(String text, PrivateKey key,String cipherAlgo) throws Exception
	    {
	        String encryptedText;
	        byte[] cipherText = encrypt(text.getBytes("UTF8"),key,cipherAlgo);
	        encryptedText = encodeBASE64(cipherText);
	        return encryptedText;
	    }


	    //"RSA/ECB/PKCS1Padding"

	    public static byte[] decrypt(byte[] text, PrivateKey key,String cipherAlgo) throws Exception
	    {
	        byte[] dectyptedText = null;
	        // decrypt the text using the private key
	        Cipher cipher = Cipher.getInstance(cipherAlgo);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        dectyptedText = cipher.doFinal(text);
	        return dectyptedText;

	    }

	    public static byte[] decrypt(byte[] text, PublicKey key,String cipherAlgo) throws Exception
	    {
	        byte[] dectyptedText = null;
	        // decrypt the text using the private key
	        Cipher cipher = Cipher.getInstance(cipherAlgo);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        dectyptedText = cipher.doFinal(text);
	        return dectyptedText;

	    }




	    public static String decrypt(String text, PrivateKey key,String cipherAlgo) throws Exception
	    {
	        String result;
	        // decrypt the text using the private key
	        byte[] dectyptedText = decrypt(decodeBASE64(text),key,cipherAlgo);
	        result = new String(dectyptedText, "UTF8");
	        return result;

	    }

	    public static String decrypt(String text, PublicKey key,String cipherAlgo) throws Exception
	    {
	        String result;
	        // decrypt the text using the private key
	        byte[] dectyptedText = decrypt(decodeBASE64(text),key,cipherAlgo);
	        result = new String(dectyptedText, "UTF8");
	        return result;

	    }


	    public static String getKeyAsString(Key key)
	    {
	        // Get the bytes of the key
	        byte[] keyBytes = key.getEncoded();
	        return encodeBASE64(keyBytes);
	    }


	    public static PrivateKey getPrivateKeyFromString(String key) throws Exception
	    {
	        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
	        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodeBASE64(key));
	        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
	        return privateKey;
	    }


	    public static PublicKey getPublicKeyFromString(String key) throws Exception
	    {
	        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
	        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodeBASE64(key));
	        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	        return publicKey;
	    }

	    public static String encodeBASE64(byte[] bytes)
	    {
	    	//return new String (org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(bytes));
	    	return new String (org.apache.commons.codec.binary.Base64.encodeBase64(bytes));
	    }

	    private static byte[] decodeBASE64(String text) throws IOException
	    {
	    	return org.apache.commons.codec.binary.Base64.decodeBase64(text);

	     //  return  new BASE64Decoder().decodeBuffer(text);

	    }
	    
	    public static String sign(String plainText, PrivateKey privateKey,String algo) throws Exception {
	        Signature privateSignature = Signature.getInstance(algo);
	        privateSignature.initSign(privateKey);
	        privateSignature.update(plainText.getBytes("UTF-8"));

	        byte[] signature = privateSignature.sign();

	        return encodeBASE64(signature);
	    }
	    
	    public static boolean verify(String plainText, String signature, PublicKey publicKey,String algo) throws Exception {
	        Signature publicSignature = Signature.getInstance(algo);
	        publicSignature.initVerify(publicKey);
	        publicSignature.update(plainText.getBytes("UTF-8"));

	        byte[] signatureBytes = decodeBASE64(signature);

	        return publicSignature.verify(signatureBytes);
	    }



	    public static void main(String[] args) throws Exception {

	        RSAUtil util = new RSAUtil();
	        KeyPair kp = RSAUtil.generateKey(1024);
	        PublicKey publicKey = kp.getPublic();
	        String message = "anish";
	        
	        String algo = "SHA256withRSA";
	        
	       String signMessage=  sign(message, kp.getPrivate(),algo);
	       
	       System.out.println(signMessage);
	       
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo = "md2WithRSA";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="md5WithRSA";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="sha1WithRSA";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="sha384WithRSA";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="sha512WithRSA";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="RSASSA-PSS";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="SHA1WithRSA/PSS";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied" + verify(message, signMessage, publicKey,algo) );
	       
	       algo="SHA224WithRSA/PSS";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied " + verify(message, signMessage, publicKey,algo) );
	       
	       algo="SHA384WithRSA/PSS";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied " + verify(message, signMessage, publicKey,algo) );
	       
	       algo="SHA1withRSAandMGF1";
	       signMessage=  sign(message, kp.getPrivate(),algo);
	       System.out.println("Verfied " + verify(message, signMessage, publicKey,algo) );
	       
	       System.exit(0);

	        String p = RSAUtil.encodeBASE64(kp.getPublic().getEncoded());

	        String q = RSAUtil.encodeBASE64(kp.getPrivate().getEncoded());

	        //System.out.println(RSAUtil.encodeBASE64(kp.getPublic().getEncoded()));

	        //System.out.println();

	        //System.out.println(RSAUtil.encodeBASE64(kp.getPrivate().getEncoded()));

	        //String encryptedMessage =  RSAUtil.encrypt(message,kp.getPublic());

	//
//	        String pubkey=
//	                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgGT1GrEtcLBjHd8EHNdbNFyM+8G6bEdkbYdHv\n" +
//	                "4S0BdQGgZO+Q6tZ1DXYyRby+LdoGtfcvkn1fKUiamwSzexrkP6uQY0OZwIoMT0qtYtliWydCx70e\n" +
//	                "Sdqyrm/7Cz1HCdqETYIEmI7W/9GbY1KLz2uzMyDYaI+Keiv4GkO8TQ7m5QIDAQAB";
	//
//	        String privkey =
//	                "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKAZPUasS1wsGMd3wQc11s0XIz7w\n" +
//	                "bpsR2Rth0e/hLQF1AaBk75Dq1nUNdjJFvL4t2ga19y+SfV8pSJqbBLN7GuQ/q5BjQ5nAigxPSq1i\n" +
//	                "2WJbJ0LHvR5J2rKub/sLPUcJ2oRNggSYjtb/0ZtjUovPa7MzINhoj4p6K/gaQ7xNDublAgMBAAEC\n" +
//	                "gYBfC3zYRxMaLkerq4mZ+TmDWjgfdmeDgg4M9n7G1Tx9v/PuP94Ff5U/unUwFTye/uOP1llgEayC\n" +
//	                "YSTsPBmHYA8u/68SkUictoPPdnYL2AIGZvsazxI8iT/METbDG2y42R6Z0QWZIeAn3s18o0C+Zi73\n" +
//	                "Syo8ZgVgk6rIG8aD3frFxQJBANByQsIDsQCg8kAPa30pJivZKTA25ChqJsbpm4LFfTpVDfeWOwWg\n" +
//	                "SgwqLSkmOSDqBUomUiQxlPFfoSVdVF8pKIsCQQDEn1xaZbJrYhJJd0Nbijo+Y6MTVFQZDgZyRiwJ\n" +
//	                "0+kDV0C2eg3+fWSa0WFkS2HDVfXGEb9YVpKZrfm0Qzq+GqxPAkEAmWPr0l/rCf5mJlPykokMaOoG\n" +
//	                "UE+keEUdQfU4lfQEYj+i5pYr2skIlIkY8JYLJjhwKg+nFLFT3Ie1ywwyAVEFXwJANJZKpQK+DWpV\n" +
//	                "acC0Cy+VFEqhuvG67FiL8NRDwv0iPPqBHEzYoU/4ME//tEtVAmFjMm5ctsuwudmGB2hTtbR8kQJB\n" +
//	                "AJ8LcT0dCTG3m0sjrD1shHMBykbq4ksutE1TdMoldbJN89vrqdr3Zu5DiVNlD3JBhqnidIyY9Nbz\n" +
//	                "oqYR7FRPAGc=";
	//
//	        System.out.println(pubkey);
//	        System.out.println(privkey);


	        PublicKey publicKeyObj = RSAUtil.getPublicKeyFromString(p);
	        PrivateKey privatekeyObj = RSAUtil.getPrivateKeyFromString(q);

	        String algobkp = "RSA/ECB/PKCS1Padding";
	         algo = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	        String encryptedMessage =  RSAUtil.encrypt(message,publicKeyObj,algo);
	        System.out.println(encryptedMessage);
	        System.out.println();
	        String decryptMessage =  RSAUtil.decrypt(encryptedMessage,privatekeyObj,algo);
	        System.out.println(decryptMessage);
	        
	        
	        



	    }

}
