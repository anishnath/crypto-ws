package cipher;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;


/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

public class ThreeFish {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static String encrypt(final String message, final String password, final String algo) throws Exception {
		int blockkeysize = 128;
		if (algo.equalsIgnoreCase("THREEFISH-256")) {
			blockkeysize = 32;
		}
		if (algo.equalsIgnoreCase("THREEFISH-512")) {
			blockkeysize = 64;
		}

		String plaintextKey = Utils.generateKey(algo, 1024, password);

		byte[] plaintextKeyarr = plaintextKey.getBytes();

		byte[] SECRET_1024 = new byte[blockkeysize];

		System.arraycopy(plaintextKeyarr, 0, SECRET_1024, 0, blockkeysize);

		final SecretKey secretKey = new SecretKeySpec(SECRET_1024, algo);

		SecretKeySpec sks = new SecretKeySpec(Utils.decodeBASE64(plaintextKey), algo);
		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[128]));
		byte[] hasil = cipher.doFinal(message.getBytes());
		String s = Utils.toBase64Encode(hasil);
		return s;

	}

	public static String decrypt(final String message, final String password, final String algo) throws Exception {
		int blockkeysize = 128;
		if (algo.equalsIgnoreCase("THREEFISH-256")) {
			blockkeysize = 32;
		}
		if (algo.equalsIgnoreCase("THREEFISH-512")) {
			blockkeysize = 64;
		}

		byte[] base64 = Utils.decodeBASE64(message);

		String plaintextKey = Utils.generateKey(algo, 1024, password);

		byte[] plaintextKeyarr = plaintextKey.getBytes();

		byte[] SECRET_1024 = new byte[blockkeysize];

		System.arraycopy(plaintextKeyarr, 0, SECRET_1024, 0, blockkeysize);

		final SecretKey secretKey = new SecretKeySpec(SECRET_1024, algo);

		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[128]));
		byte[] hasil = cipher.doFinal(base64);
		return new String(hasil);

	}

	public static void main(String[] args) throws Exception {

		String message = "hello Anish @  8gWifi.org";
		String password = "hello";
		String algo = "THREEFISH-512";

		String encryt = encrypt(message, password, algo);

		String s = decrypt(encryt, password, algo);
		
		System.out.println(s);

		algo = "THREEFISH-256";
		encryt = encrypt(message, password, algo);

		System.out.println(encryt);

		s = decrypt(encryt, password, algo);

		System.out.println(s);

		algo = "THREEFISH-1024";
		encryt = encrypt(message, password, algo);

		System.out.println(encryt);

		s = decrypt(encryt, password, algo);

		System.out.println(s);

	}

}
