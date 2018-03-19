package ntru;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cacerts.Utils;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.sign.NtruSign;
import net.sf.ntru.sign.SignatureKeyPair;
import net.sf.ntru.sign.SignatureParameters;
import pojo.ntrupojo;

/**
 * @author aninath
 * Demo @ https://8gwifi.org
 */
public class NTRUSEncryptionDecryption {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		
		
		String s = "AucIAHD5clcYcIvwiGI%2BuTowMF5hC%2F0YvggnzIRajx%2BUGLe0qGNR%2BlCMdtiMwLiZ3vY1uZ7m7sCq%0A8JYxYyOFI4oieC0HU1vnpGa796VQ1K0ZokdBoZbfu3pFGh4Z8743E3POhgt0BByl7UbbD%2BnghboG%0AHNE6E%2FnhqCiOjOCl0lMXZJLJEl6JSQq5yPxa8Egdjjl5R6Sh6OSFEmQrXofryByIE7YSInYvCGJ5%0ALanXjIb65iJ1CJEa4n7%2BKroloyP5%2Bs%2FighNLO94B1gxylxcUxK3ckEu8fWhRcxZ4mQfKAsgnqKvx%0AceVYChiRlcKGZuWN%2FL63v1xx0rluoDfxoc2lijX8iOV%2Bn9TQXGMVcG%2FpWzMAfCm%2BYk4uyohvFUB%2F%0AkOdoQ5NcfCwMd5H7MjA70xsiMpp7kRLaVB2HmDV2aHS4PUBwnszmJ%2F9YQCP65ha8J4HDZa9KQuOg%0AeXgTyvetB7gEVOGdOXC%2BkcBLmWyIjHofd15UnwG8p6vZcsnLwqsbzCq20WZT7VFsU9%2BFb1Jx00Ln%0ABrfIoL2NC15CF96cPH0vyVRuIdYgCfsoeNaM01TQhKTo35qsGvS%2BS9QuJdTFO0BNNYf53jgFyyLf%0ADkDcnhTw%2ByJ5AbrfDpxAtByBp3NqfZ3GIDQ4AgsZIHCFNmvD7k1mf%2Frlhd%2BoBUtxggF7fjuuSZt8%0Alr%2BWza%2BGputQt%2FYHYEI%2FLltBLJ5RSlWg%2BxLgwxbyj2oQ8orUacGjSeI9%2FWN1ENaFXiEPDKR5pMDS%0ABvr8f8hn29BhgkUVI0OzR8aOEPNnUphQNo6aoZf0urZyPntX2hNxAdN%2BprGbAfxPzhN32Tbho5Xj%0AD2EhYbFVkjlkuWzzK8mA0uJv5ZLbqF4Pz1HdI5iaHbeAtevAtY1e%2BHeIzTOWJmxzH7zJxSBXgBCN%0ArgxW9FmswRYc8tFLBta63WxhNe7MRFQ%2BRS%2BuZ%2BlIiN%2FbJR9qD6EC0vWu1rFm01ui0oHFD2T%2F5szU%0AEIaEjzZqdcWMsY1MN2n4%2F0mGoc7KXhdFyhCYru7sIZDjF6ytDRAifRRJlxFx9lQnWaEzwnnCzqKP%0AnhwGKMuIWQWjBIaNzPJSXl4wi7uEpqra5ETere43X8QXhE%2F%2Bcwcy7%2FwgjGY5iEIHgibihLZEctIP%0AUyYHW1l%2Bzh9x4adzI6M3IZOp9auEOpdnwxqFaaFjYomg3zveFaNLmIklUfR0CMpOz03ocBYXgUCs%0AXdCCxd3v4rXSvUMqOCXqL7%2Fhwa63Hx6HIAg7vBhVVsFp9oS033lDOOrZyAr0BIOspSfNsJTwws%2Fp%0AUnFdfRSidRK6tXJ6j1G2S7lKs5zfyKJwzL5kHEOFnrqzZgEZuMLNa6BqZ97tEXdWr%2BUV2aGLLuoW%0A";
		String p_msg="helloanish nath";
		String p_ntru="APR2011_743_FAST";
		
		String path = System.getProperty("java.io.tmpdir");
		String fullPath = path + "/" + UUID.randomUUID().toString();

		File privfile = new File(fullPath);
		File pubfile1 = new File(fullPath + ".pub");
		
		
		FileOutputStream stream = new FileOutputStream(pubfile1);
		try {
			stream.write(s.getBytes());
		} finally {
			stream.close();
		}

		
		InputStream stream1 = new ByteArrayInputStream(Utils.decodeBASE64(s));
		
		System.out.println(new NTRUSEncryptionDecryption().encrypt(p_ntru, p_msg, stream1));
		
		
		// encrypt();
		System.out.println();
		sign();

		ntrupojo ntrupojo = new NTRUSEncryptionDecryption().generateNTRUKeys("APR2011_743_FAST");

		String privateKey = ntrupojo.getPrivatekey();
		String publicKey = ntrupojo.getPublickey();

		byte[] pr = Utils.decodeBASE64(privateKey);
		byte[] pu = Utils.decodeBASE64(publicKey);

		

		 stream = new FileOutputStream(privfile);
		try {
			stream.write(pr);
		} finally {
			stream.close();
		}

		stream = new FileOutputStream(pubfile1);
		try {
			stream.write(pu);
		} finally {
			stream.close();
		}

		System.out.println("privfile " + fullPath);

		InputStream privStream = new FileInputStream(fullPath);
		InputStream pubStream = new FileInputStream(fullPath + ".pub");

		// EncryptionPrivateKey encryptionPrivateKey = new
		// EncryptionPrivateKey(privStream);
		// EncryptionPublicKey encryptionPublicKey = new
		// EncryptionPublicKey(pubStream);
		//
		// NtruEncrypt ntru = new
		// NTRUSEncryptionDecryption().getNTRU("APR2011_743_FAST");
		//
		// String msg = "Anish @8gwifi.org";
		// System.out.println(" Before encryption: " + msg);
		//
		// // encrypt the message with the public key created above
		// byte[] enc = ntru.encrypt(msg.getBytes(), encryptionPublicKey);
		//
		// EncryptionKeyPair encryptionKeyPair = new
		// EncryptionKeyPair(encryptionPrivateKey, encryptionPublicKey);
		//
		// byte[] dec = ntru.decrypt(enc, encryptionKeyPair);
		//
		// // print the decrypted message
		// System.out.println(" After decryption: " + new String(dec));

		ntrupojo ntrupojo2 = new NTRUSEncryptionDecryption().encrypt("APR2011_743_FAST", "Hello Anish @*gwifi.org",
				pubStream);

		System.out.println(ntrupojo2);

		privStream = new FileInputStream(fullPath);
		pubStream = new FileInputStream(fullPath + ".pub");

		System.out.println(new NTRUSEncryptionDecryption().decrypt("APR2011_743_FAST", ntrupojo2.getMessage(),
				pubStream, privStream));

		pubfile1.delete();
		privfile.delete();

	}

	public ntrupojo generateNTRUKeys(String param) {
		return generateNTRUKeys(param, false, null, null);
	}

	public ntrupojo generateNTRUKeys(String param, boolean isEcrypted, String password, String saltp) {
		NtruEncrypt ntru = getNTRU(param);
		byte[] salt = null;
		EncryptionKeyPair kp = null;
		if (!isEcrypted) {
			kp = ntru.generateKeyPair();
		} else {

			if (saltp != null) {
				salt = saltp.getBytes();
			} else {
				salt = ntru.generateSalt();
			}
			if (password != null) {
				kp = ntru.generateKeyPair(password.toCharArray(), salt);
			} else {
				kp = ntru.generateKeyPair();
			}
		}
		ntrupojo ntrupojo = new ntrupojo();
		ntrupojo.setNtruparam(param);
		ntrupojo.setPublickey(Utils.toBase64Encode(kp.getPublic().getEncoded()));
		ntrupojo.setPrivatekey(Utils.toBase64Encode(kp.getPrivate().getEncoded()));
		if (isEcrypted) {
			ntrupojo.setMessage("Salt used =[" + Utils.toBase64Encode(salt) +"]");
		}
		return ntrupojo;

	}

	public ntrupojo encrypt(String param, String message, InputStream publicKey) throws Exception {
		ntrupojo ntrupojo = null;
		try {

			// create an instance of NtruEncrypt with a standard parameter set
			EncryptionPublicKey encryptionPublicKey = new EncryptionPublicKey(publicKey);

			NtruEncrypt ntru = getNTRU(param);

			// encrypt the message with the public key created above
			byte[] enc = ntru.encrypt(message.getBytes(), encryptionPublicKey);

			String encryptedMessage = Utils.toBase64Encode(enc);

			ntrupojo = new ntrupojo();
			ntrupojo.setMessage(encryptedMessage);

		} catch (Exception e) {
			throw new Exception(e);
		}
		return ntrupojo;
	}

	public ntrupojo decrypt(String param, String message, InputStream publicKey, InputStream prInputStream)
			throws Exception {
		ntrupojo ntrupojo = null;
		try {
			
			EncryptionPrivateKey encryptionPrivateKey = new EncryptionPrivateKey(prInputStream);
			EncryptionPublicKey encryptionPublicKey = new EncryptionPublicKey(publicKey);

			// create an instance of NtruEncrypt with a standard parameter set

			NtruEncrypt ntru = getNTRU(param);

			// create an encryption key pair
			EncryptionKeyPair encryptionKeyPair = new EncryptionKeyPair(encryptionPrivateKey, encryptionPublicKey);

			byte b[] = Utils.decodeBASE64(message);

			// decrypt the message with the private key created above
			byte[] dec = ntru.decrypt(b, encryptionKeyPair);

			String decryptedMessage = new String(dec);

			ntrupojo = new ntrupojo();
			ntrupojo.setMessage(decryptedMessage);

		} catch (Exception e) {
			throw new Exception(e);
		}

		return ntrupojo;
	}

	private NtruEncrypt getNTRU(String param) {
		NtruEncrypt ntru = null;

		if (param.trim().equalsIgnoreCase("EES1087EP2")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1087EP2);
		}
		if (param.trim().equalsIgnoreCase("EES1087EP2_FAST")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1087EP2_FAST);
		}
		if (param.trim().equalsIgnoreCase("EES1171EP1")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1171EP1);
		}
		if (param.trim().equalsIgnoreCase("EES1171EP1_FAST")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1171EP1_FAST);
		}
		if (param.trim().equalsIgnoreCase("EES1499EP1")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1499EP1);
		}

		if (param.trim().equalsIgnoreCase("EES1499EP1_FAST")) {
			ntru = new NtruEncrypt(EncryptionParameters.EES1499EP1_FAST);
		}
		if (param.trim().equalsIgnoreCase("APR2011_439")) {
			ntru = new NtruEncrypt(EncryptionParameters.APR2011_439);
		}
		if (param.trim().equalsIgnoreCase("APR2011_439_FAST")) {
			ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
		}
		if (param.trim().equalsIgnoreCase("APR2011_743")) {
			ntru = new NtruEncrypt(EncryptionParameters.APR2011_743);
		}

		if (param.trim().equalsIgnoreCase("APR2011_743_FAST")) {
			ntru = new NtruEncrypt(EncryptionParameters.APR2011_743_FAST);
		}

		if (ntru == null) {
			// Set the Default
			ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
		}

		return ntru;
	}

	private static void sign() {
		System.out.println("NTRU signature");

		// create an instance of NtruSign with a test parameter set
		NtruSign ntru = new NtruSign(SignatureParameters.TEST157);

		// create an signature key pair
		SignatureKeyPair kp = ntru.generateKeyPair();

		String msg = "The quick brown fox";
		System.out.println("  Message: " + msg);

		// sign the message with the private key created above
		byte[] sig = ntru.sign(msg.getBytes(), kp);

		// verify the signature with the public key created above
		boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());

		System.out.println("  Signature valid? " + valid);
	}
}
