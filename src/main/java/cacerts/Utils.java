package cacerts;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.openssl.PEMWriter;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class Utils {

	public static String generateKey(String alg, int size, String seed) throws Exception {
		SecureRandom securerandom = SecureRandom.getInstance("SHA1PRNG");
		securerandom.setSeed(seed.getBytes("UTF-8"));
		KeyGenerator kg = KeyGenerator.getInstance(alg);
		kg.init(size, securerandom);
		SecretKey sk = kg.generateKey();
		return toBase64Encode(sk.getEncoded());
	}

	public static KeyPair generateRSAKeyPair(String algo, int bits) throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algo, "BC");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG",
	            "BC");
		kpGen.initialize(bits, random);

		return kpGen.generateKeyPair();
	}

	public static BigInteger getRandomBigInteger() {
		Random rand = new Random();
		BigInteger result = new BigInteger(4, rand); // (2^4-1) = 15 is the
														// maximum value
		return result;
	}

	public static byte[] decodeBASE64(String text) throws IOException {

		return new BASE64Decoder().decodeBuffer(text);

	}

	public static byte[] inputStreamToByteArray(InputStream is) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[1024];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();
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

	public static String toPem(X509Certificate keyPair) throws IOException {
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

	public static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	public static String toBase64Encode(final byte[] msg) {
		return new BASE64Encoder().encode(msg);

	}

	public static String toHexEncoded(byte[] b) {
		return Hex.encodeHexString(b);
	}

	public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);

			SecretKey key = keyAgreement.generateSecret("AES");
			return key;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			return null;
		}
	}

	// AES/GCM/NoPadding
	public static byte[] encryptString(SecretKey key, String plainText, String algo, byte[] iv) {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(algo, "BC");
			byte[] plainTextBytes = plainText.getBytes("UTF-8");
			byte[] cipherText;
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
			int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
			encryptLength += cipher.doFinal(cipherText, encryptLength);
			return (cipherText);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// AES/GCM/NoPadding
	public static byte[] encryptString(PrivateKey key, String plainText, String algo, byte[] iv) {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(algo, "BC");
			byte[] plainTextBytes = plainText.getBytes("UTF-8");
			byte[] cipherText;
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
			int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
			encryptLength += cipher.doFinal(cipherText, encryptLength);
			return (cipherText);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// AES/GCM/NoPadding
	public static byte[] encryptString(PublicKey key, String plainText, String algo, byte[] iv) {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(algo, "BC");
			byte[] plainTextBytes = plainText.getBytes("UTF-8");
			byte[] cipherText;
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
			int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
			encryptLength += cipher.doFinal(cipherText, encryptLength);

			return (cipherText);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// "AES/GCM/NoPadding"
	/**
	 * Elliptic Curve Decryption...
	 * @param key
	 * @param cipherText
	 * @param algo
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptString(SecretKey key, String cipherText, String algo) throws Exception {
		try {
			Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
			byte[] encryptedTextBytes = null;
			IvParameterSpec ivSpec = null;
			Cipher cipher = Cipher.getInstance(algo, "BC");

			ByteBuffer buffer = ByteBuffer.wrap(new Base64().decode(cipherText));
			byte[] saltBytes = new byte[16];
			buffer.get(saltBytes, 0, saltBytes.length);

			ivSpec = new IvParameterSpec(saltBytes);

			encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length];

			buffer.get(encryptedTextBytes);

			byte[] plainText;

			cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
			plainText = new byte[cipher.getOutputSize(encryptedTextBytes.length)];
			int decryptLength = cipher.update(encryptedTextBytes, 0, encryptedTextBytes.length, plainText, 0);
			decryptLength += cipher.doFinal(plainText, decryptLength);

			String s = new String(plainText, "UTF-8");

			return s.getBytes();
		} catch (Exception e) {
			// e.printStackTrace();
			throw new Exception(e);
		}
	}

	public static byte[] hexToBytes(String string) {
		int length = string.length();
		byte[] data = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
					+ Character.digit(string.charAt(i + 1), 16));
		}
		return data;
	}

	public static boolean isHexNumber(String cadena) {
		try {
			Long.parseLong(cadena, 16);
			return true;
		} catch (NumberFormatException ex) {
			// Error handling code...
			return false;
		}
	}

}
