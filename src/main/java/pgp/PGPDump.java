package pgp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Iterator;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

/**
 * 
 * @author anishnath
 *
 */
public class PGPDump {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}


	private FileInputStream fileInputStream;

	public FileInputStream getFileInputStream() {
		return fileInputStream;
	}

	public void setFileInputStream(FileInputStream fileInputStream) {
		this.fileInputStream = fileInputStream;
	}

	public static String getSignature(String algIdd) {

		int algId;
		try {
			algId = Integer.valueOf(algIdd);
		} catch (NumberFormatException e) {
			algId = Integer.parseInt(algIdd, 16);
			// builder.append(algId);
			// TODO Auto-generated catch block
			// e.printStackTrace();
		}

		switch (algId) {

		case 0:
			return "Signature of a binary document. (0x00) ";
		case 1:
			return "Signature of a canonical text document (0x01)";
		case 2:
			return "Standalone signature. (0x02)";
		case 10:
			return "Generic certification of a User ID and Public-Key packet (0x10)";
		case 11:
			return "Persona certification of a User ID and Public-Key packet (0x11)";
		case 12:
			return "Casual certification of a User ID and Public-Key packet (0x12)";
		case 13:
			return "Positive certification of a User ID and Public-Key packet.(0x13)";
		case 18:
			return "Subkey Binding Signature (0x18)";
		case 19:
			return "Primary Key Binding Signature (0x19)";
		case 31:
			return "Signature directly on a key (0x1F)";
		case 20:
			return "Key revocation signature (0x20)";
		case 28:
			return "Subkey revocation signature (0x28)";
		case 30:
			return "Certification revocation signature (0x30)";
		case 40:
			return "Timestamp signature. (0x40)";
		case 50:
			return "Third-Party Confirmation signature.. (0x50)";
		}

		return "unknown";
	}

	public static String getAlgorithm(int algId) {
		switch (algId) {
		case PublicKeyAlgorithmTags.RSA_GENERAL:
			return "RSA_GENERAL";
		case PublicKeyAlgorithmTags.RSA_ENCRYPT:
			return "RSA_ENCRYPT";
		case PublicKeyAlgorithmTags.RSA_SIGN:
			return "RSA_SIGN";
		case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
			return "ELGAMAL_ENCRYPT";
		case PublicKeyAlgorithmTags.DSA:
			return "DSA";
		case PublicKeyAlgorithmTags.ECDH:
			return "ECDH";
		case PublicKeyAlgorithmTags.ECDSA:
			return "ECDSA";
		case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
			return "ELGAMAL_GENERAL";
		case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
			return "DIFFIE_HELLMAN";
		}

		return "unknown";
	}

	public static String getVersion(int algId) {
		switch (algId) {
		case 4:
			return "Ver 4 (New)";
		}
		return "Ver 3 (Old)";

	}

	public static String getHashAgorithm(int algId) {
		switch (algId) {
		case 1:
			return "MD5";
		case 2:
			return "SHA-1";
		case 3:
			return "RIPE-MD/160";
		case 4:
			return "Reserved";
		case 5:
			return "Reserved";
		case 6:
			return "Reserved";
		case 7:
			return "Reserved";
		case 8:
			return "SHA256";
		case 9:
			return "SHA384";
		case 10:
			return "SHA512";
		case 11:
			return "SHA224";
		}

		return "Private/Experimental algorithm";
	}

	public static String getEncryptionAlgorithm(int algId) {
		switch (algId) {
		case 0:
			return "Plaintext or unencrypted data";
		case 1:
			return "IDEA";
		case 2:
			return "TripleDES";
		case 3:
			return "CAST5";
		case 4:
			return "Blowfish";
		case 5:
			return "Reserved";
		case 6:
			return "Reserved";
		case 7:
			return "AES with 128-bit key";
		case 8:
			return "AES with 192-bit key";
		case 9:
			return "AES with 256-bit key";
		case 10:
			return "Twofish with 256-bit key";
		}

		return "Private/Experimental algorithm";
	}

	public static void main(String[] args) throws Exception {

		String s = "-----BEGIN PGP MESSAGE-----\n" + "Version: BCPG v1.58\n" + "\n"
				+ "hIwDmCS94uDDx9kBA/93avQQMrxbWt8ODyDNH+yCT/39nehUkN94vAkxQ7oDJQ57\n"
				+ "Nv9l1IeB6ANgsFeHt3RZRKZI937E3ZELhKM+JXaJ0IWvDalf4I/Ds8Id1WXXIev7\n"
				+ "501dVoJOIcEGnqs4f1VKiLgV6bALswbpEBbGo1eT0/TNDHWdVS1EA0oMr/X+gdJE\n"
				+ "AVvsLUcI54/8RXsoZabn18arHCgXdWAMA+0hg9nkN6wTwx3txPF4QyuCf4tzE0qB\n"
				+ "VdUyJG3s5otDVAk59Pc3SfExk40=\n" + "=jlcq\n" + "-----END PGP MESSAGE-----";

		final String publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + "Version: BCPG v1.58\n" + "\n"
				+ "mI0EWiOMeQEEAImCEQUnSQ54ee+mnkANsjyvZm2QsC1sGIBEpmyJbh2xWuluJ/KV\n"
				+ "TIUSqbkLOEq4COIlzG0fhuruUWBM2+ANazq5jkxLrYmHX4AwA2Q6jvd3xE8B1uVj\n"
				+ "qT0TEKyZtmBwesEswUxb+vOwVLdWKXpcySXtIQhoKWAUVzG7e5uEawyXABEBAAG0\n"
				+ "BWFuaXNoiJwEEAECAAYFAlojjHkACgkQmCS94uDDx9lHewP/UtsSk3lyj5GnHyoT\n"
				+ "HZMz+sUFpFlan7agqHf6pV2Pgdb9OMCVauMwl9bjPY9HSHQg/a3gTQ5qNq9txiI2\n"
				+ "4Fso2Q3AR6XcVk2wQxS6prJ9imPi1npXarCwZkEgWLXWLuQLHoxRWHf9olUqeW7P\n"
				+ "kwQlJ1K9Ib85pCTvx16DN7QwQv8=\n" + "=Qteg\n" + "-----END PGP PUBLIC KEY BLOCK-----";

		final String privakeyKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + "Version: BCPG v1.58\n" + "\n"
				+ "lQH+BFojjHkBBACJghEFJ0kOeHnvpp5ADbI8r2ZtkLAtbBiARKZsiW4dsVrpbify\n"
				+ "lUyFEqm5CzhKuAjiJcxtH4bq7lFgTNvgDWs6uY5MS62Jh1+AMANkOo73d8RPAdbl\n"
				+ "Y6k9ExCsmbZgcHrBLMFMW/rzsFS3Vil6XMkl7SEIaClgFFcxu3ubhGsMlwARAQAB\n"
				+ "/gQDApBPMSbTsvQjYNgi3vBAHHkJ5YurFXAPWeZ87jXJ/DdruVoK5cXqdgg4g5Sz\n"
				+ "9ZBE2rkcJ7qL54I2zMEZaXmQeqANqfhRuJH2E8DlRW6wbt2jU5WorD/a/5iTcjGu\n"
				+ "/AfBRIktji4LW/BcsKnXirDZK12IjxYjyCHv4AY3P/v6Osf91zdmg9C1S7vuwz5I\n"
				+ "2hXqJBj7jhyZ2y/C6CP84Rnr7XyvqQxNV1BDIJH21z4er15axuY23pywA6I8Qqwm\n"
				+ "I5vaSmJlBHwpQ22Fh5EkltMIHNqcpQ50HoNL/XKwXy1PvgyEA79462RvTY6Bj6JE\n"
				+ "WPEHCFa9mvuubeXOO7D1S9pM3ygpuwQiR9F4EFCWU5m5xR1Wr2QlftiJI7Fhyg7M\n"
				+ "ttkyjEW0AX6RbGgbhKnCOaiDO7CJpSULwwkMfOGAWYwrsxcJh8LqZVEUVrH//Ajo\n"
				+ "kNPN+u9X0U/g4Vt5aKuEygFkF0QcLruOW/BUgpH4KFUWtAVhbmlzaIicBBABAgAG\n"
				+ "BQJaI4x5AAoJEJgkveLgw8fZR3sD/1LbEpN5co+Rpx8qEx2TM/rFBaRZWp+2oKh3\n"
				+ "+qVdj4HW/TjAlWrjMJfW4z2PR0h0IP2t4E0OajavbcYiNuBbKNkNwEel3FZNsEMU\n"
				+ "uqayfYpj4tZ6V2qwsGZBIFi11i7kCx6MUVh3/aJVKnluz5MEJSdSvSG/OaQk78de\n" + "gze0MEL/\n" + "=5jHf\n"
				+ "-----END PGP PRIVATE KEY BLOCK-----";

		String pubs = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + "\n"
				+ "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\n"
				+ "rVNbxYe38JyZrFXyTLF+k6zutL9GTw==\n" + "=t0L6\n" + "-----END PGP PUBLIC KEY BLOCK-----";

		String pubke1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + "Version: BCPG v1.58\n" + "\n"
				+ "mQENBGC3Rm8BCADQxRZI6vxQ5QK47+fttpeyj3SxfV0auhzL5htIzXrCX2/RuraD\n"
				+ "MrTibqaJCQlYNV6H09J2k1TEejokPQt6pOva4Nfyd+oEkTsJAeR5dvcrkjF4h/Fe\n"
				+ "AU8XMNiXTOZ55db4jV1JYD+ADoVp3GUXHGUk9igTmQ/rgrG1tHYgrvsE0Zv5t18Y\n"
				+ "mygjLM7CPu3paDFCMwvC5JU5pFX+NucBZ98V5A0AP2KRaWapXmkIhs5KuvSACb2V\n"
				+ "a/0ypxxwAAP7d0Ajv4j2OBJukyEbnuSH4NXKH4kYiVzm63FsZ+KSxRT4LWkaD0OS\n"
				+ "aA0Bw3f0Gp/n5atnK68al7DF7LFNDaCkJEdXABEBAAG0FmFuaXNoMmdvb2RAeWFo\n"
				+ "b28uY28uaW6JARwEEAECAAYFAmC3Rm8ACgkQRMwQiYwMH1XhnAgAoYVC+Bc5rdR6\n"
				+ "u3zdC6JlEkg+n2Pzdytm6cLWcvLPp0ASorcVCC5eICUJXoqOnXkw+yeUVD0auFW9\n"
				+ "YpKspvXODsV+KoXQMYHmJRM4zhCgMLQa00pPTXnyDuzVtXzfrk+6uZ2AyG+Cu9WN\n"
				+ "UoSmhXGRfKl0UMwpDGEhe+MrFudQWtlk4Rl2gdnYzvMKJ84kX/EdcT9Hvf+LR9a/\n"
				+ "n3idJhdlqxl+7cyySCNJhfUoA+BxfeoaW/Sx78R3Qq81nd01ZKIOAsHjnA8DRt+Y\n"
				+ "RdCycl8PyVo2v8AeRk3cXgmXYzdX4nc6NjiexCUiHdi5Wd1UlWXwWlv5vUGTCSNp\n" + "8by+nRm06Q==\n" + "=5whh\n"
				+ "-----END PGP PUBLIC KEY BLOCK-----\n" + "";

		String key1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + "Version: BCPG v1.58\n" + "\n"
				+ "mQINBGC3RqgBEAC2/d/fsgnw3vW6RGrwtohjGrb5EqbzASfnmRj2sPbZtFrZzELK\n"
				+ "T/z3J1e/DC+S8T3qehFW1vMs9ZwmBsTGdzbHVckF6+zRE2v0qQGta61PSUKptzX0\n"
				+ "0DFDBDO+Od3kX7mCEHSRCLD5l2d1034p/4nm6LnCeIEnGDJggnMVYL40eG23YcEv\n"
				+ "kG7zpWg5bG84gcAmxsTezRk/EV7SHDq3BXZ5KIQDsLVvFiW3aJzj+TRfRuGR6lsR\n"
				+ "a6vaWGQ9tRRZ7g01j7Uwr1ngRupSVMoVpk/xM8u6hw7rWbYcemJfrCG/HZb9lbpw\n"
				+ "LbsgvI9gIbH/EJjz1L2CvSwNCIUVg+plLCxjbEzXujN1nj4AnLhrtjUM2BkVZU9f\n"
				+ "k9jH9s8CzCTfhuhlYtB8Ny61rMF5xzLDIqiZv9zLNo8Za5fKypGVMMyFDY5qjMvY\n"
				+ "1UNVaK7s4JYn0LJWLjws+XHmLINSlJ5uQtMBCQg3cKyIYUE5Fq0ZYrDYP2x8ArcR\n"
				+ "YEozpQ1KBPLTOo5bL15xvoRtqdWJ0Au/0sjI4OjWzhz+Zzhiw7Fh13Es5ZEc6voO\n"
				+ "IqcTr8Hid8cLQzVUr3iA54qxQqCyTxsnMqUGR67uIwccKCQV979OUuQNu+2fzE2R\n"
				+ "eQzVN6Qxe4nBmtIJkNwYlJMdXLF+khi1PAOHGJ8Dguoq+/w9s11/wunbnQARAQAB\n"
				+ "tBZhbmlzaDJnb29kQHlhaG9vLmNvLmluiQIcBBABAgAGBQJgt0aoAAoJEOmk/bvk\n"
				+ "wTPDSFsP/j8hsuRhF4k24CT1r4tI8/O7YE+jXbDle9qn0ZPW+j0y/kOUG/pFK/3f\n"
				+ "RVOCYqbcMKxiy7wwdxynFUN60wniUARzmKQ9M9K8WWS8Nu8gj+LmVxdmIt8Lx5bW\n"
				+ "TzfZrj9RsIztrJalwxh3xJh2rHwH8YlJjNUu1YULhYGg8zN+GJddeGH+S3jNj0GA\n"
				+ "ZpMeg/7jKEpqhg7ltZHUcthDEgaAcvC2jHsWAmUHtXm8SgQ9ftU81FfxanR83ZPG\n"
				+ "MH4u6TlWaCtLn48+sksqnk5voZQIazMsuWMmP3cGu4ivBUrInHNWkgTvjKLFXDLN\n"
				+ "2ObeT3g/fEEgBd2o1kIbzS2GvSPPEb48POwkYFsXSDKm5cGqQKpcN3Mt/y1vKHAN\n"
				+ "S8NEy0cC41U0hoV/VVqDEJIcbWiE8x8bi8TV2/g5NAV49YRkCWpg5TIZ3oe4Qt05\n"
				+ "nvXskw5p1a0bwx+tgqBAUqV/1WgTbIBeWLONFTuR1u3Msg9UbdRwAAiS+c2klUgL\n"
				+ "UEamP9uw9gLpqz8D2nvLSBxVdFwEbnU0xHMTB9/lg1QT5x47vBU5QgMEIsudDZPG\n"
				+ "vWSSv8xgqcM/3hvfmyQgEg83SnFx57wnYhqet9nuket1ldOG0oczwj+unSH33sxm\n"
				+ "rRu+QSztFQKDOaLBfpHE5KP3e+41rBtRrJOZCRKpvMoKj4sJzykd\n" + "=PgsE\n"
				+ "-----END PGP PUBLIC KEY BLOCK-----\n" + "";

		String priv1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + "Version: Keybase OpenPGP v1.0.0\n"
				+ "Comment: https://keybase.io/crypto\n" + "\n"
				+ "xcASBGC4docTBSuBBAAiAwME1dIGgNXWCm83w/FH3P1YAZIv0fU0aSjx0El/tT39\n"
				+ "yT5y2Ej+odpyrGfnW4aRjwCv8azd7JzvBzQugPykwPQ9qsCaLxKJdJfMUIHn2LOn\n"
				+ "E5rh0oUfhwkQGVRHIKs2qEiu/gkDCBrryqDntVzTYKJq6sUSbgOJiYl2waOQCfeJ\n"
				+ "GCo/Cly1F3pByeTM7ho66fMZhlwj/iQTd4B5nYGnxQtBWm3xkK9abG6aFGBtmFwy\n"
				+ "CMgzLtsfORlR0swhbubKQcHWf5QbzRhIZWxsbyAgPGhlbGxvQHNkYXNkLmNvbT7C\n"
				+ "jwQTEwoAFwUCYLh2hwIbLwMLCQcDFQoIAh4BAheAAAoJEAIR+RmIEecp2MMBfi/A\n"
				+ "iNrtkwzOZbGYXgVX9H4hpjpgl/oWMsq/aOdJlI3GkoylXgsD2SI8jgIhJbtHMgGA\n"
				+ "0rVm6feN7shi7lB95s1CnFXhOqxmeKCZcgqz0bbDH3y+wbsR3ONmApK5kR8pbT2s\n"
				+ "x6UEYLh2hxMIKoZIzj0DAQcCAwSOsx69VEeDSM1AWtnOrmuR5ykKohSVpzTcmLHN\n"
				+ "PSgtCjqg0/c4gulaKwOumeEqOWFOmVomBmV9+zf8+aJJ0UJ2/gkDCFmwMqQkDFB/\n"
				+ "YBVbpTQRahf+5OBCxx6K+gyTE+cqs10BJy51xeeGhJiEqIuVSr48Mjt/LxrUuJ0w\n"
				+ "pyWFzWPFc+Yj/4YTk/LqotGV+IOArf/CwCcEGBMKAA8FAmC4docFCQ8JnAACGy4A\n"
				+ "agkQAhH5GYgR5ylfIAQZEwoABgUCYLh2hwAKCRBsgXBa10puA7UqAPsE4r118Ahg\n"
				+ "PSzwvA3Fi+04P6SLviyosStOs2WlyoHwnAEAv9K+iVWCAfm2M1/rBYauwajc01Xn\n"
				+ "IUeBe7NfGMjd4lPo5QGA+HPjXe2VJqYG5Dv2nF9OB0GGzhWR4e8hBybVOSl0nPtV\n"
				+ "1qSEyrkzxwLZCASAWiHOAX9tKugYFOPdQQ6xuEtkY4r2FX560WAHbJGEoYudh43X\n"
				+ "RghqP7+h6WrP8oQMRnTptCfHpQRguHaHEwgqhkjOPQMBBwIDBGORdGvk0nR+IHNY\n"
				+ "PNLyp1rx+CGGbj796Wcelq4D6POXKaK1ADUtEQU70d5fgYx0H2hbYwwJuygMDb0Y\n"
				+ "5a7D+T/+CQMIj/p6AiXVR+5g5gCXSM2jqDylsJLslN+yZfqbJR3SLuft10HWTYnL\n"
				+ "/lbMRaqdb3rgVytRe47VCbKpn0J1apGFCgKhKx/N9l5k8H4+y2q/bMLAJwQYEwoA\n"
				+ "DwUCYLh2hwUJDwmcAAIbLgBqCRACEfkZiBHnKV8gBBkTCgAGBQJguHaHAAoJEMtP\n"
				+ "cRxoIEq8wPAA/RfEXrEFBYuXyE6t8reofFDpxGrZH9Sxn4K51S+o0IpNAP4rwwv3\n"
				+ "g12UHiGPXPeqjA1149OrAhMirRGpC1grV9Sm0w7wAYCKJbpfdyVZhLMznj4qYmzx\n"
				+ "BVXkOjTWZdFpiJYEk3UF3cyhPzxvM1uoDcaHRqS8i5sBgN8LpspM/m0BuaPVj7As\n"
				+ "H879kCm2OUfwDek3kQk4iz+YxO9LWMd0HFznLA4kp4Mc4Q==\n" + "=g3K4\n"
				+ "-----END PGP PRIVATE KEY BLOCK-----\n" + "";

		String pub2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + "Version: Keybase OpenPGP v1.0.0\n"
				+ "Comment: https://keybase.io/crypto\n" + "\n"
				+ "xm8EYLh2hxMFK4EEACIDAwTV0gaA1dYKbzfD8Ufc/VgBki/R9TRpKPHQSX+1Pf3J\n"
				+ "PnLYSP6h2nKsZ+dbhpGPAK/xrN3snO8HNC6A/KTA9D2qwJovEol0l8xQgefYs6cT\n"
				+ "muHShR+HCRAZVEcgqzaoSK7NGEhlbGxvICA8aGVsbG9Ac2Rhc2QuY29tPsKPBBMT\n"
				+ "CgAXBQJguHaHAhsvAwsJBwMVCggCHgECF4AACgkQAhH5GYgR5ynYwwF+L8CI2u2T\n"
				+ "DM5lsZheBVf0fiGmOmCX+hYyyr9o50mUjcaSjKVeCwPZIjyOAiElu0cyAYDStWbp\n"
				+ "943uyGLuUH3mzUKcVeE6rGZ4oJlyCrPRtsMffL7BuxHc42YCkrmRHyltPazOUgRg\n"
				+ "uHaHEwgqhkjOPQMBBwIDBI6zHr1UR4NIzUBa2c6ua5HnKQqiFJWnNNyYsc09KC0K\n"
				+ "OqDT9ziC6VorA66Z4So5YU6ZWiYGZX37N/z5oknRQnbCwCcEGBMKAA8FAmC4docF\n"
				+ "CQ8JnAACGy4AagkQAhH5GYgR5ylfIAQZEwoABgUCYLh2hwAKCRBsgXBa10puA7Uq\n"
				+ "APsE4r118AhgPSzwvA3Fi+04P6SLviyosStOs2WlyoHwnAEAv9K+iVWCAfm2M1/r\n"
				+ "BYauwajc01XnIUeBe7NfGMjd4lPo5QGA+HPjXe2VJqYG5Dv2nF9OB0GGzhWR4e8h\n"
				+ "BybVOSl0nPtV1qSEyrkzxwLZCASAWiHOAX9tKugYFOPdQQ6xuEtkY4r2FX560WAH\n"
				+ "bJGEoYudh43XRghqP7+h6WrP8oQMRnTptCfOUgRguHaHEwgqhkjOPQMBBwIDBGOR\n"
				+ "dGvk0nR+IHNYPNLyp1rx+CGGbj796Wcelq4D6POXKaK1ADUtEQU70d5fgYx0H2hb\n"
				+ "YwwJuygMDb0Y5a7D+T/CwCcEGBMKAA8FAmC4docFCQ8JnAACGy4AagkQAhH5GYgR\n"
				+ "5ylfIAQZEwoABgUCYLh2hwAKCRDLT3EcaCBKvMDwAP0XxF6xBQWLl8hOrfK3qHxQ\n"
				+ "6cRq2R/UsZ+CudUvqNCKTQD+K8ML94NdlB4hj1z3qowNdePTqwITIq0RqQtYK1fU\n"
				+ "ptMO8AGAiiW6X3clWYSzM54+KmJs8QVV5Do01mXRaYiWBJN1Bd3MoT88bzNbqA3G\n"
				+ "h0akvIubAYDfC6bKTP5tAbmj1Y+wLB/O/ZAptjlH8A3pN5EJOIs/mMTvS1jHdBxc\n" + "5ywOJKeDHOE=\n" + "=Q/RI\n"
				+ "-----END PGP PUBLIC KEY BLOCK-----\n" + "";

		System.out.println(new PGPDump().parsePGP(pub2));

	}

	public String parsePGP(String pgpdata) throws Exception {
		
		String path = System.getProperty("java.io.tmpdir");
		String dummyFile = path + "/" + UUID.randomUUID().toString();
		InputStream stream = new ByteArrayInputStream(pgpdata.getBytes(StandardCharsets.UTF_8));
		File f1 = new File(dummyFile);
		FileUtils.copyInputStreamToFile(stream, f1);
		setFileInputStream(new FileInputStream(dummyFile));
		
		PGPObjectFactory pgpFact = new PGPObjectFactory(PGPUtil.getDecoderStream(getFileInputStream()),
				new JcaKeyFingerprintCalculator());

		StringBuilder builder = new StringBuilder();
		Object nextObject = pgpFact.nextObject();
		while (nextObject != null) {
			if (nextObject instanceof PGPEncryptedDataList) {
				builder.append(processEncryptedDataList((PGPEncryptedDataList) nextObject));
			} else if (nextObject instanceof PGPPublicKeyRing) {
				builder.append(processPublicKeyring((PGPPublicKeyRing) nextObject));
			} else if (nextObject instanceof PGPSecretKeyRing) {
				PGPSecretKeyRing keyRing = (PGPSecretKeyRing) nextObject;
				Iterator<PGPPublicKey> publicKeyRingIter = keyRing.getPublicKeys();
				builder.append(dumpPublicKeys(publicKeyRingIter));
				PGPSecretKey pgpSecretKey = keyRing.getSecretKey();
				if (pgpSecretKey != null) {
					builder.append(dumpSecretKeys(pgpSecretKey));
				}
			} else {
				builder.append("Found an object called: " + nextObject.getClass() + "\n");
			}

			try {
				nextObject = pgpFact.nextObject();
			} catch (IOException e) {
				break;
			}
		}

		try {
			File file = new File(dummyFile);
			file.delete();
		} catch (Exception ex) {
			// DO Nothing
		}
		return builder.toString();
	}

	private String dumpSecretKeys(PGPSecretKey pgpSecretKey) throws Exception {
		StringBuilder builder = new StringBuilder();
		builder.append("Secret Key ");
		builder.append("\n");
		builder.append("\t Key ID: " + Long.toHexString(pgpSecretKey.getKeyID()));
		builder.append("\n");
		builder.append("\t s2kUsage: " + pgpSecretKey.getS2KUsage());
		builder.append("\n");
		if (pgpSecretKey.getS2K() != null) {
			builder.append("\t Hash Algo: " + getHashAgorithm(pgpSecretKey.getS2K().getHashAlgorithm()));
			builder.append("\n");
			builder.append("\t Itertaion Count: " + pgpSecretKey.getS2K().getIterationCount());
			builder.append("\n");
			builder.append("\t Protection Mode: " + pgpSecretKey.getS2K().getProtectionMode());
			builder.append("\n");
			builder.append("\t Type: " + pgpSecretKey.getS2K().getType());
			builder.append("\n");
			builder.append("\t IV: (Hex) " + new String(Hex.encode(pgpSecretKey.getS2K().getIV())));
			builder.append("\n");
		}
		builder.append("\t Key Encryption Algo: " + getEncryptionAlgorithm(pgpSecretKey.getKeyEncryptionAlgorithm()));
		builder.append("\n");
		builder.append("\t is MasterKey: " + pgpSecretKey.isMasterKey());
		builder.append("\n");
		builder.append("\t is Signing Key: " + pgpSecretKey.isSigningKey());
		builder.append("\n");
		builder.append("\t is Private Key Empty: " + pgpSecretKey.isPrivateKeyEmpty());
		builder.append("\n");
		builder.append("\t Encoded: " + new String(Hex.encode(pgpSecretKey.getEncoded())));
		builder.append("\n");
		builder.append("UserIds ");
		Iterator userids = pgpSecretKey.getUserIDs();
		while (userids.hasNext()) {
			String user = (String) userids.next();
			builder.append("\t User: " + user);
			builder.append("\n");
		}

		return builder.toString();

	}

	// private void processEncryptedDataList(PGPEncryptedDataList nextObject) {
//		// TODO Auto-generated method stub
//		
//	}
//	
	private String processEncryptedDataList(PGPEncryptedDataList edl) throws Exception {
		PGPSecretKey pgpSecKey = null;

		StringBuilder builder = new StringBuilder();
		int count = 0;
		PGPPublicKeyEncryptedData pked = null;
		while (count != edl.size()) {
			Object obj = edl.get(count);
			if (obj instanceof PGPPublicKeyEncryptedData) {
				builder.append("Found some PGPPublicKeyEncryptedData, ");
				pked = (PGPPublicKeyEncryptedData) obj;
				long keyId = pked.getKeyID();
				builder.append("Encrypted by " + asHex(keyId));

				PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
						PGPUtil.getDecoderStream(getFileInputStream()), new JcaKeyFingerprintCalculator());

				Iterator keyRingIter = pgpSec.getKeyRings();

				while (keyRingIter.hasNext()) {
					PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
					Iterator keyIter = keyRing.getSecretKeys();

					while (keyIter.hasNext()) {
						pgpSecKey = (PGPSecretKey) keyIter.next();
					}
				}
				if (pgpSecKey != null) {
					// TODO: Produce more information here about the key, such as user id
					builder.append("Found matching key " + asHex(pgpSecKey.getKeyID()) + ": ");
					builder.append(secKeyDump(pgpSecKey));
					builder.append("\n");
					break;
				} else {
					builder.append("Can't find signing key in key ring.");
					builder.append("\n");
				}
			} else {
				builder.append("Found an object in the PGPEncryptedDataList of: " + obj.getClass());
				builder.append("\n");
			}

			count++;
		}
		return builder.toString();
	}

	private String secKeyDump(PGPSecretKey pgpSecKey) {
		if (pgpSecKey == null) {
			return "Key is null";
		}

		StringBuffer sb = new StringBuffer("SecretKey: ");
		sb.append(asHex(pgpSecKey.getKeyID()));
		sb.append('\n');

		PGPPublicKey pubKey = pgpSecKey.getPublicKey();

		// need to grab the public key information or something
		// for data about the "master key"

		if (pubKey != null) {
			userDataDump(sb, pubKey);
		} else {
			sb.append("Cannot find associated public key\n");
		}

		return sb.toString();
	}

	private String asHex(long l) {
		return Long.toHexString(l).substring(8);
	}

	private void userDataDump(StringBuffer sb, PGPPublicKey pubKey) {
		Iterator i = pubKey.getUserIDs();
		sb.append("Id list: ");
		if ((i != null) && i.hasNext()) {
			while (i.hasNext()) {
				String id = (String) i.next();
				sb.append('\"').append(id).append("\" ");
			}
		} else {
			sb.append("<none>");
		}
		sb.append('\n');

		/*
		 * i = pubKey.getUserAttributes(); sb.append("Attribute list: "); if ((i !=
		 * null) && i.hasNext()) { while (i.hasNext()) { String id = (String) i.next();
		 * sb.append("\"").append(id).append("\" "); } } else { sb.append("<none>"); }
		 */
	}

	private String processPublicKeyring(PGPPublicKeyRing nextObject) throws Exception {

		Iterator<PGPPublicKey> it = nextObject.getPublicKeys();

		return dumpPublicKeys(it);

	}

	private String dumpPublicKeys(Iterator<PGPPublicKey> it) throws IOException {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		while (it.hasNext()) {
			PGPPublicKey pgpKey = (PGPPublicKey) it.next();

			if (first) {
				builder.append("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
				builder.append("\n");
				first = false;
			} else {
				builder.append("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
				builder.append("\n");
			}
			builder.append("\t Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
			builder.append("\n");
			builder.append("\t Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
			builder.append("\n");
			builder.append("\t Encoded: " + new String(Hex.encode(pgpKey.getEncoded())));
			builder.append("\n");
			if (pgpKey.getTrustData() != null) {
				builder.append("\t Trust Data: " + new String(Hex.encode(pgpKey.getTrustData())));
				builder.append("\n");
			}
			builder.append("\t Creation Time: " + pgpKey.getCreationTime());
			builder.append("\n");
			builder.append("\t Bit Strength: " + pgpKey.getBitStrength());
			builder.append("\n");
			builder.append("\t Has Revocation: " + pgpKey.hasRevocation());
			builder.append("\n");
			builder.append("\t Has EncryptionKey: " + pgpKey.isEncryptionKey());
			builder.append("\n");
			builder.append("\t Has MasterKey: " + pgpKey.isMasterKey());
			builder.append("\n");

			Iterator<String> userIds = pgpKey.getUserIDs();
			while (userIds.hasNext()) {
				String userID = userIds.next();
				builder.append("\t UserId: " + userID);
				builder.append("\n");
			}

			Iterator<PGPUserAttributeSubpacketVector> pgpIterator = pgpKey.getUserAttributes();
			while (pgpIterator.hasNext()) {

				PGPUserAttributeSubpacketVector attributeSubpacketVector = (PGPUserAttributeSubpacketVector) pgpIterator
						.next();
				if (attributeSubpacketVector != null) {
					attributeSubpacketVector.getImageAttribute();
				}
			}

			Iterator sigIter = pgpKey.getKeySignatures();

			while (sigIter.hasNext()) {
				builder.append("Signature Packet");
				builder.append("\n");
				PGPSignature sig = (PGPSignature) sigIter.next();
				builder.append("\t Hash Algo: " + getHashAgorithm(sig.getHashAlgorithm()));
				builder.append("\n");
				builder.append("\t Version: " + getVersion(sig.getVersion()));
				builder.append("\n");
				builder.append("\t Key ID: " + Long.toHexString(sig.getKeyID()));
				builder.append("\n");
				builder.append("\t Signature Type : " + getSignature(Long.toHexString(sig.getSignatureType())));
				builder.append("\n");

				PGPSignatureSubpacketVector pgpSignatureSubpacketVector = sig.getHashedSubPackets();
//				if(pgpSignatureSubpacketVector!=null)
//				{
//					builder.append(pgpSignatureSubpacketVector.getIssuerKeyID());
//					builder.append(pgpSignatureSubpacketVector.getKeyExpirationTime());
//					builder.append(pgpSignatureSubpacketVector.getSignerUserID());
//				}					
			}

		}
		return builder.toString();
	}

	private static void processSecretKeyring(PGPSecretKeyRing nextObject) throws Exception {
	}

}
