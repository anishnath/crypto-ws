package pgp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import cacerts.Utils;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class PGPEncryptionDecryption {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static byte[] decrypt(byte[] encrypted, char[] passPhrase)
			throws IOException, PGPException, NoSuchProviderException {
		InputStream in = new ByteArrayInputStream(encrypted);

		in = PGPUtil.getDecoderStream(in);

		JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
		PGPEncryptedDataList enc;
		Object o = pgpF.nextObject();

		//
		// the first object might be a PGP marker packet.
		//
		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) enc.get(0);

		InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(
				new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC")
						.build(passPhrase));

		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

		PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

		PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

		return Streams.readAll(ld.getInputStream());
	}

	public static byte[] encrypt(byte[] clearData, char[] passPhrase, String fileName, int algorithm, boolean armor)
			throws IOException, PGPException, NoSuchProviderException {

		if (fileName == null) {
			fileName = PGPLiteralData.CONSOLE;
		}

		byte[] compressedData = compress(clearData, fileName, CompressionAlgorithmTags.ZIP);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		OutputStream out = bOut;
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(algorithm).setSecureRandom(new SecureRandom()).setProvider("BC"));
		encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passPhrase).setProvider("BC"));

		OutputStream encOut = encGen.open(out, compressedData.length);

		encOut.write(compressedData);
		encOut.close();

		if (armor) {
			out.close();
		}

		return bOut.toByteArray();
	}

	private static byte[] compress(byte[] clearData, String fileName, int algorithm) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
		OutputStream cos = comData.open(bOut); // open it with the final
												// destination

		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

		// we want to generate compressed data. This might be a user option
		// later,
		// in which case we would pass in bOut.
		OutputStream pOut = lData.open(cos, // the compressed output stream
				PGPLiteralData.BINARY, fileName, // "filename" to store
				clearData.length, // length of clear data
				new Date() // current time
		);

		pOut.write(clearData);
		pOut.close();

		comData.close();

		return bOut.toByteArray();
	}

	public String decryptMsg(String msg, String privateKey, char[] passwd) throws IOException, NoSuchProviderException {

		String path = System.getProperty("java.io.tmpdir");
		String dummyFile = path + "/" + UUID.randomUUID().toString();
		InputStream stream = new ByteArrayInputStream(msg.getBytes());
		File f1 = new File(dummyFile);
		FileUtils.copyInputStreamToFile(stream, f1);

		String dummyFile2 = path + "/" + UUID.randomUUID().toString();
		InputStream stream2 = new ByteArrayInputStream(privateKey.getBytes());
		File f2 = new File(dummyFile2);
		FileUtils.copyInputStreamToFile(stream2, f2);

		InputStream in = new BufferedInputStream(new FileInputStream(f1));
		InputStream keyIn = new BufferedInputStream(new FileInputStream(dummyFile2));
		String s = decryptMsg(in, keyIn, passwd);
		keyIn.close();
		in.close();

		f1.deleteOnExit();
		f2.deleteOnExit();

		return s;

	}

	private static String decryptMsg(InputStream in, InputStream keyIn, char[] passwd)
			throws IOException, NoSuchProviderException {

		in = PGPUtil.getDecoderStream(in);
		StringBuilder builder = new StringBuilder();

		try {
			String path = System.getProperty("java.io.tmpdir");
			String outFileName = path + "/" + UUID.randomUUID().toString();

			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			//
			// the first object might be a PGP marker packet.
			//
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			//
			// find the secret key
			//
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
					new JcaKeyFingerprintCalculator());

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();

				sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
			}

			if (sKey == null) {
				throw new PGPException("secret key for message not found.");
			}

			InputStream clear = pbe
					.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

			JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

			Object message = plainFact.nextObject();

			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

				message = pgpFact.nextObject();
			}

			if (message instanceof PGPLiteralData) {

				PGPLiteralData ld = (PGPLiteralData) message;

				InputStream unc = ld.getInputStream();
				OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));

				Streams.pipeAll(unc, fOut);

				fOut.close();

				final String s = Utils.readFile(outFileName, Charset.defaultCharset());

				builder.append(s);

				// Silently Delete the temporary File Security DONOT Store any
				// Thing
				// on
				// the servers
				try {
					File file = new File(outFileName);
					file.delete();
				} catch (Exception ex) {
					// DO Nothing
				}

			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("message is not a simple encrypted file - type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					builder.append("\nmessage failed integrity check\n");
				} else {
					builder.append("\nmessage integrity check passed\n");
				}
			} else {
				builder.append("\nno message integrity check\n");
			}
		} catch (PGPException e) {

			if (e.getUnderlyingException() != null) {
				return e.getMessage();
			}
			return e.getMessage();
		}

		return builder.toString();
	}

	public String encryptMsg(String msg, String publicKey, boolean armor, boolean withIntegrityCheck)
			throws IOException, NoSuchProviderException, PGPException {

		String path = System.getProperty("java.io.tmpdir");
		String outFileName = path + "/" + UUID.randomUUID().toString();

		String dummyFile = path + "/" + UUID.randomUUID().toString();
		InputStream stream = new ByteArrayInputStream(publicKey.getBytes());
		File f1 = new File(dummyFile);
		FileUtils.copyInputStreamToFile(stream, f1);

		OutputStream out = new BufferedOutputStream(new FileOutputStream(outFileName));
		PGPPublicKey encKey = PGPExampleUtil.readPublicKey(dummyFile);
		encryptMsg(out, msg, encKey, armor, withIntegrityCheck);
		out.close();

		final String s = Utils.readFile(outFileName, Charset.defaultCharset());

		// Silently Delete the temporary File Security DONOT Store any
		// Thing
		// on
		// the servers
		try {
			File file = new File(outFileName);
			file.delete();
		} catch (Exception ex) {
			// DO Nothing
		}
		f1.deleteOnExit();

		return s;

	}

	private static void encryptMsg(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
			boolean withIntegrityCheck) throws IOException, NoSuchProviderException {

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		String path = System.getProperty("java.io.tmpdir");
		String dummyFileName = path + "/" + UUID.randomUUID().toString();
		try {

			FileOutputStream fileOutputStream = new FileOutputStream(dummyFileName);
			fileOutputStream.write(fileName.getBytes());
			fileOutputStream.close();

			byte[] bytes = PGPExampleUtil.compressFile(dummyFileName, CompressionAlgorithmTags.ZIP);

			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck)
							.setSecureRandom(new SecureRandom()).setProvider("BC"));

			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

			OutputStream cOut = encGen.open(out, bytes.length);

			cOut.write(bytes);
			cOut.close();

			if (armor) {
				out.close();
			}

		} catch (PGPException e) {

			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		} finally {
			try {
				File file = new File(dummyFileName);
				file.delete();
			} catch (Exception ex) {
				// DO Nothing
			}
		}
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		String passPhrase = "Anish Nath";
		char[] passArray = passPhrase.toCharArray();

		byte[] original = "Hello world 8gwifi.org".getBytes();
		System.out.println("Starting PGP test");
		byte[] encrypted = encrypt(original, passArray, "hello", PGPEncryptedDataGenerator.CAST5, true);

		System.out.println("\nencrypted data = '" + new String(encrypted) + "'");
		byte[] decrypted = decrypt(encrypted, passArray);

		System.out.println("\ndecrypted data = '" + new String(decrypted) + "'");

		encrypted = encrypt(original, passArray, "hello", PGPEncryptedDataGenerator.AES_256, false);

		System.out.println(
				"\nencrypted data = '" + new String(org.bouncycastle.util.encoders.Hex.encode(encrypted)) + "'");
		decrypted = decrypt(encrypted, passArray);

		System.out.println("\ndecrypted data = '" + new String(decrypted) + "'");

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

		PGPEncryptionDecryption encryptionDecryption = new PGPEncryptionDecryption();
		String p = encryptionDecryption.encryptMsg("Hello Anish Nath...@8gwifi.org", publicKey, true, true);
		System.out.println(p);
		System.out.println(encryptionDecryption.decryptMsg(p, privakeyKey, "anish".toCharArray()));

	}
}
