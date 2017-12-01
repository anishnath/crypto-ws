package pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.UUID;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class VerifyAndSignedFileProcessor {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	/*
	 * verify the passed in file as being correctly signed.
	 */
	public static String verifyFile(InputStream in, InputStream keyIn)  {
		try {
			in = PGPUtil.getDecoderStream(in);

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

			PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

			PGPOnePassSignature ops = p1.get(0);

			PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

			InputStream dIn = p2.getInputStream();
			int ch;
			PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
					new JcaKeyFingerprintCalculator());

			PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
			FileOutputStream out = new FileOutputStream(p2.getFileName());

			ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

			while ((ch = dIn.read()) >= 0) {
				ops.update((byte) ch);
				out.write(ch);
			}

			out.close();

			PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

			if (ops.verify(p3.get(0))) {
				return "signature verified.";
			} else {
				return "signature verification failed.";
			}
		} catch (Exception e) {
			String s = e.getMessage();
			if(s==null)
			{
				return "Invalid PGP Message File ";
			}
			return e.getMessage();
		}
	}


	private static void signFile(String fileName, InputStream keyIn, char[] pass)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
		try {
			
			String path = System.getProperty("java.io.tmpdir");
			String fullPathPublicKey = path + "/" + UUID.randomUUID().toString();

			OutputStream out = new FileOutputStream(fullPathPublicKey);

	System.out.println(fullPathPublicKey);

			PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
			PGPPrivateKey pgpPrivKey = pgpSec
					.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
			PGPSignatureGenerator sGen = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
							.setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

			Iterator it = pgpSec.getPublicKey().getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

				spGen.setSignerUserID(false, (String) it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}

			PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);

			BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

			sGen.generateOnePassVersion(false).encode(bOut);

			File file = new File(fileName);
			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
			OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
			FileInputStream fIn = new FileInputStream(file);
			int ch;

			while ((ch = fIn.read()) >= 0) {
				lOut.write(ch);
				sGen.update((byte) ch);
			}

			lGen.close();

			sGen.generate().encode(bOut);

			cGen.close();
			
			out.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception {
		

		if (args[0].equals("-s")) {
			if (args[1].equals("-a")) {
				FileInputStream keyIn = new FileInputStream(args[3]);
				signFile(args[2], keyIn,  args[4].toCharArray());
			} else {
				FileInputStream keyIn = new FileInputStream(args[2]);
				signFile(args[1], keyIn,args[3].toCharArray());
			}
		} else if (args[0].equals("-v")) {
			FileInputStream in = new FileInputStream(args[1]);
			FileInputStream keyIn = new FileInputStream(args[2]);

			System.out.println(verifyFile(in, keyIn));
		} else {
			System.err.println("usage: SignedFileProcessor -v|-s [-a] file keyfile [passPhrase]");
		}
	}
}