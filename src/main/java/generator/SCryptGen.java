package generator;

import org.bouncycastle.crypto.generators.SCrypt;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.util.Base64;
/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class SCryptGen {
	
	public SCryptGen()
	{
		
	}

	private static final Charset CHARSET = Charset.forName("UTF-8");
	
	public  String SCryptPasswordEncoder(String passphrase, String salt, int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) throws Exception {
		
		if (!isPowerOf2(cpuCost)) {
			throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
		}
		
		byte[] b = SCrypt.generate(passphrase.getBytes(), salt.getBytes(), cpuCost, memoryCost, parallelization,
				keyLength);
		
		StringBuilder sb = new StringBuilder();
		sb.append(encodePart(b));
		
		return sb.toString();
		
	}

	public static void main(String[] args) {

		String passphrase = "anish";
		String salt = "8gwifi.org"; // salt
		int cpuCost = 4; // CPU //cpuCost
		int memoryCost = 400
				; // the block size, //memoryCost
		int parallelization = 400; // Parallelization parameter
		int keyLength = 100; // the length of the key to generate

		if (!isPowerOf2(cpuCost)) {
			throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
		}

		byte[] b = SCrypt.generate(passphrase.getBytes(), salt.getBytes(), cpuCost, memoryCost, parallelization,
				keyLength);

		String params = Long
				.toString(((int) (Math.log(cpuCost) / Math.log(2)) << 16L) | memoryCost << 8 | parallelization, 16);

		StringBuilder sb = new StringBuilder((salt.getBytes().length + b.length) * 2);
		sb.append("$").append(params).append('$');
		sb.append(encodePart(salt.getBytes())).append('$');
		sb.append(encodePart(b));

		System.out.println(sb.toString());

		String rawPassword = "anish";
		String encodedPassword = sb.toString();
		System.out.println(decodeAndCheckMatches(rawPassword, encodedPassword));

	}

	public static boolean decodeAndCheckMatches(String rawPassword, String encodedPassword) {
		String[] parts = encodedPassword.split("\\$");

		if (parts.length != 4) {
			return false;
		}

		long params = Long.parseLong(parts[1], 16);
		byte[] salt = decodePart(parts[2]);
		byte[] derived = decodePart(parts[3]);

		int cpuCost = (int) Math.pow(2, params >> 16 & 0xffff);

		int memoryCost = (int) params >> 8 & 0xff;
		int parallelization = (int) params & 0xff;

		System.out.println("cpuCost " + cpuCost);
		System.out.println("memoryCost " + memoryCost);
		System.out.println("parallelization " + parallelization);

		byte[] generated = SCrypt.generate(rawPassword.toString().getBytes(), salt, cpuCost, memoryCost,
				parallelization, 100);
		// byte[] generated = SCrypt.generate(encode(rawPassword), salt,
		// cpuCost, memoryCost, parallelization, keyLength);

		if (derived.length != generated.length) {
			return false;
		}

		int result = 0;
		for (int i = 0; i < derived.length; i++) {
			result |= derived[i] ^ generated[i];
		}
		return result == 0;
	}

	public static byte[] decodePart(String part) {
		return Base64.getDecoder().decode(encode(part));
	}

	public static String encodePart(byte[] part) {
		return decode(Base64.getEncoder().encode(part));
	}

	public static byte[] encode(CharSequence string) {
		try {
			ByteBuffer bytes = CHARSET.newEncoder().encode(CharBuffer.wrap(string));
			byte[] bytesCopy = new byte[bytes.limit()];
			System.arraycopy(bytes.array(), 0, bytesCopy, 0, bytes.limit());

			return bytesCopy;
		} catch (CharacterCodingException e) {
			throw new IllegalArgumentException("Encoding failed", e);
		}
	}

	public static String decode(byte[] bytes) {
		try {
			return CHARSET.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
		} catch (CharacterCodingException e) {
			throw new IllegalArgumentException("Decoding failed", e);
		}
	}

	private static boolean isPowerOf2(int x) {
		return ((x & (x - 1)) == 0);
	}

}
