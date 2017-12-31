package pbe;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;

public class PBEEncryptDecrypt {
	
	private static final byte[] iv =new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	
	 static {
	        Security.addProvider(new BouncyCastleProvider());
	    }



	    public static String encrypt(final String message, final String password, final String algo, int rounds,final String salt) throws Exception {
	        byte[] encryptedText = null;
	        try {
	            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
	            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
	            IvParameterSpec ivspec = new IvParameterSpec(iv);

	            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt.getBytes(), rounds,ivspec);
	            Cipher cipher = Cipher.getInstance(algo);
	            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
	            encryptedText = cipher.doFinal(message.getBytes());

	        } catch (Exception ex) {
	            throw new Exception(ex);
	        }

	        return Utils.toBase64Encode(encryptedText);
	    }

	    public static String decrypt(final String message, final String password, final String algo, int rounds,final String salt) throws Exception {
	        byte[] dectyptedText = null;
	        try {
	            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
	            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
	            byte[] decryptMessage = Utils.decodeBASE64(message);
	            IvParameterSpec ivspec = new IvParameterSpec(iv);
	            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt.getBytes(), rounds,ivspec);
	            Cipher cipher = Cipher.getInstance(algo);
	            cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
	            dectyptedText = cipher.doFinal(decryptMessage);
	        } catch (Exception ex) {
	        	System.out.println("algo -- Exception " + algo);
	            throw new Exception(ex);
	        }
	        return new String(dectyptedText);

	    }


	    public static byte[] encryptFile(byte[] fisX, final String password, final String algo, int rounds) throws Exception {


	        String path = System.getProperty("java.io.tmpdir");
	        String fullPath = path + "/" + UUID.randomUUID().toString();
	        byte[] b = null;
	        //System.out.println(fullPath);
	        try {
	            FileOutputStream outFile = new FileOutputStream(fullPath);
	            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	            SecretKeyFactory secretKeyFactory = SecretKeyFactory
	                    .getInstance(algo);
	            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	            byte[] salt = new byte[8];
	            Random random = new Random();
	            random.nextBytes(salt);

	            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, rounds);
	            Cipher cipher = Cipher.getInstance(algo);
	            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
	            outFile.write(salt);

	            byte[] output = cipher.doFinal(fisX);
	            if (output != null)
	                outFile.write(output);


	            outFile.flush();
	            outFile.close();

	            FileInputStream fiss = new FileInputStream(fullPath);

	            b = IOUtils.toByteArray(fiss);

	            //Silently Delete the temprary File
	            try {
	                File file = new File(fullPath);
	                file.delete();
	            } catch (Exception ex) {
	                //DO Nothing
	            }
	        }catch (Exception ex)
	        {
	            throw new Exception(ex);
	        }

	        return b;

	    }


	    public static byte[] decryptFile(InputStream fis, final String password, final String algo, int rounds) throws Exception {

	        String path = System.getProperty("java.io.tmpdir");
	        String fullPath = path + "/" + UUID.randomUUID().toString();
	        byte[] b = null;
	        //System.out.println(fullPath);

	        try{
	        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	        SecretKeyFactory secretKeyFactory = SecretKeyFactory
	                .getInstance(algo);
	        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
	        byte[] salt = new byte[8];
	        fis.read(salt);
	        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, rounds);
	        Cipher cipher = Cipher.getInstance(algo);
	        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
	        FileOutputStream fos = new FileOutputStream(fullPath);
	        byte[] in = new byte[64];
	        int read;
	        while ((read = fis.read(in)) != -1) {
	            byte[] output = cipher.update(in, 0, read);
	            if (output != null)
	                fos.write(output);
	        }

	        byte[] output = cipher.doFinal();
	        if (output != null)
	            fos.write(output);

	        fis.close();
	        fos.flush();

	        FileInputStream fiss = new FileInputStream(fullPath);
	        b= IOUtils.toByteArray(fiss);

	        //Silently Delete the temprary File
	        try {
	            File file = new File(fullPath);
	            file.delete();
	        }catch (Exception ex)
	        {
	            //DO Nothing
	        }
	        }catch (Exception ex)
	        {

	            throw new Exception(ex.getMessage());
	        }


	        return b;
	    }

	    byte[] concatenateByteArrays(byte[] a, byte[] b) {
	        byte[] result = new byte[a.length + b.length];
	        System.arraycopy(a, 0, result, 0, a.length);
	        System.arraycopy(b, 0, result, a.length, b.length);
	        return result;

}
}
