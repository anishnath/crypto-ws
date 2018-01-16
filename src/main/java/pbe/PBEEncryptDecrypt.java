package pbe;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;

/**
 * 
 * @author Anish Nath 
 * Demo @8gwifi.org
 *
 */
public class PBEEncryptDecrypt {

	

	static {
		Security.addProvider(new BouncyCastleProvider());
	}


	/**
	 * 
	 * @param message
	 * @param password
	 * @param algo
	 * @param rounds
	 * @param salt
	 * @return
	 * @throws Exception
	 * paramter salt is unused, in future if user need to passed the salt also then we can consider
	 */
	public static String encrypt(final String message, final String password, final String algo, int rounds,
			final String salt) throws Exception {
		byte[] encryptedText = null;
		try {
			// byte[] ivBytes = null;
			byte[] buffer = null;
			SecureRandom random = new SecureRandom();
			byte bytes[] = new byte[8];
			byte bytessalt[] = new byte[16];
			random.nextBytes(bytes);
			random.nextBytes(bytessalt);
			byte[] saltBytes = bytes;
			byte[] ivBytesrandom = bytessalt;

			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

			Cipher cipher = Cipher.getInstance(algo);

			IvParameterSpec ivspec = new IvParameterSpec(ivBytesrandom);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(saltBytes, rounds, ivspec);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
			encryptedText = cipher.doFinal(message.getBytes());

			buffer = new byte[saltBytes.length + ivBytesrandom.length + encryptedText.length];
			System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
			System.arraycopy(ivBytesrandom, 0, buffer, saltBytes.length, ivBytesrandom.length);
			System.arraycopy(encryptedText, 0, buffer, saltBytes.length + ivBytesrandom.length, encryptedText.length);

			return Utils.toBase64Encode(buffer);

		} catch (Exception ex) {
			throw new Exception(ex);
		}

	}

	/**
	 * 
	 * @param message
	 * @param password
	 * @param algo
	 * @param rounds
	 * @param salt
	 * @return Decrypted Text
	 * @throws Exception
	 * 
	 * paramter salt is unused, in future if user need to passed the salt also then we can consider
	 */
	public static String decrypt(final String message, final String password, final String algo, int rounds,
			final String salt) throws Exception {
		byte[] dectyptedText = null;
		try {

			ByteBuffer buffer = ByteBuffer.wrap(new Base64().decode(message));
			Cipher cipher = Cipher.getInstance(algo);
			byte[] saltBytes = new byte[8];
			buffer.get(saltBytes, 0, saltBytes.length);

			byte[] encryptedTextBytes = null;
			byte[] ivBytes1 = new byte[16];

			buffer.get(ivBytes1, 0, ivBytes1.length);

			encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes1.length];

			buffer.get(encryptedTextBytes);

			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

			IvParameterSpec ivspec = new IvParameterSpec(ivBytes1);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(saltBytes, rounds, ivspec);
			ivBytes1 = new byte[cipher.getBlockSize()];
			cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
			dectyptedText = cipher.doFinal(encryptedTextBytes);
			return new String(dectyptedText);

		} catch (Exception ex) {

			throw new Exception(ex);
		}

	}

	public static byte[] encryptFile(byte[] fisX, final String password, final String algo, int rounds)
			throws Exception {

		String path = System.getProperty("java.io.tmpdir");
		String fullPath = path + "/" + UUID.randomUUID().toString();
		byte[] b = null;
		// System.out.println(fullPath);
		try {
			FileOutputStream outFile = new FileOutputStream(fullPath);
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
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

			// Silently Delete the temprary File
			try {
				File file = new File(fullPath);
				file.delete();
			} catch (Exception ex) {
				// DO Nothing
			}
		} catch (Exception ex) {
			throw new Exception(ex);
		}

		return b;

	}

	public static byte[] decryptFile(InputStream fis, final String password, final String algo, int rounds)
			throws Exception {

		String path = System.getProperty("java.io.tmpdir");
		String fullPath = path + "/" + UUID.randomUUID().toString();
		byte[] b = null;
		// System.out.println(fullPath);

		try {
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
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
			b = IOUtils.toByteArray(fiss);

			// Silently Delete the temprary File
			try {
				File file = new File(fullPath);
				file.delete();
			} catch (Exception ex) {
				// DO Nothing
			}
		} catch (Exception ex) {

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

	public static void main(String[] args) throws Exception {

		String x = "8bitMinm";
		
		PBEEncryptDecrypt encryptDecrypt = new PBEEncryptDecrypt();

		String[] str = { "PBEWITHHMACSHA1ANDAES_128", "PBEWITHHMACSHA1ANDAES_256", "PBEWITHHMACSHA224ANDAES_128",
				"PBEWITHHMACSHA224ANDAES_256", "PBEWITHHMACSHA256ANDAES_128", "PBEWITHHMACSHA256ANDAES_256",
				"PBEWITHHMACSHA384ANDAES_128", "PBEWITHHMACSHA384ANDAES_256", "PBEWITHHMACSHA512ANDAES_128",
				"PBEWITHHMACSHA512ANDAES_256", "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
				"PBEWITHMD5AND192BITAES-CBC-OPENSSL", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", "PBEWITHMD5ANDDES",
				"PBEWITHMD5ANDRC2", "PBEWITHMD5ANDTRIPLEDES", "PBEWITHSHA1ANDDES", "PBEWITHSHA1ANDDESEDE",
				"PBEWITHSHA1ANDRC2", "PBEWITHSHA1ANDRC2_128", "PBEWITHSHA1ANDRC2_40", "PBEWITHSHA1ANDRC4_128",
				"PBEWITHSHA1ANDRC4_40", "PBEWITHSHA256AND128BITAES-CBC-BC", "PBEWITHSHA256AND192BITAES-CBC-BC",
				"PBEWITHSHA256AND256BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC", "PBEWITHSHAAND128BITRC2-CBC",
				"PBEWITHSHAAND128BITRC4", "PBEWITHSHAAND192BITAES-CBC-BC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",
				"PBEWITHSHAAND256BITAES-CBC-BC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND40BITRC2-CBC",
				"PBEWITHSHAAND40BITRC4", "PBEWITHSHAANDIDEA-CBC", "PBEWITHSHAANDTWOFISH-CBC" };
		
		for (int i = 0; i < str.length; i++) {
			
			String cipher =str [i];
			String msg = "8gWifi.org";
			int rounds = 10000;
			String s = encryptDecrypt.encrypt(msg, "123456", cipher, rounds, null);
			//System.out.println("Encrypted-- " + s);
			String decryptText = encryptDecrypt.decrypt(s, "123456", cipher, rounds, null);

			//System.out.println("Dectypted Test ==  " + decryptText);
			
			if(decryptText.equals(msg))
			{
				System.out.println("PASSED");
			}
			else {
				System.out.println("FAILED");
			}
		}

		String cipher = "PBEWITHMD5ANDDES";
		
		

	}
}
