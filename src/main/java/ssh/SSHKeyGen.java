package ssh;

import com.jcraft.jsch.JSch;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pojo.sshpojo;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 
 * @author Anish 
 * Demo @https://8gwifi.org
 *
 */

public class SSHKeyGen {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	
	public sshpojo genKeyPair(String algo, int keySize) throws Exception {
		return genKeyPair(algo,null,keySize);
	}

	public sshpojo genKeyPair(String algo,String passphrase, int keySize) throws Exception {

		sshpojo sshpojo = new sshpojo();
		int type = com.jcraft.jsch.KeyPair.UNKNOWN;
		JSch jsch = new JSch();

		if (algo != null) {
			if (algo.equalsIgnoreCase("ECDSA")) {
				// 256
				// 384
				//521
				type = com.jcraft.jsch.KeyPair.ECDSA;
			}
			if (algo.equalsIgnoreCase("DSA")) {
				//512,576,640,704,768,832,896,960,1024,2048
				type = com.jcraft.jsch.KeyPair.DSA;

			}
			if (algo.equalsIgnoreCase("RSA")) {
				// 1024,
				// 2048
				// 4096
				type = com.jcraft.jsch.KeyPair.RSA;
			}

			if (com.jcraft.jsch.KeyPair.UNKNOWN != 4) {
				type = com.jcraft.jsch.KeyPair.ECDSA;
				keySize=521;
			}
			
			com.jcraft.jsch.KeyPair kpair = com.jcraft.jsch.KeyPair.genKeyPair(jsch, type, keySize);
			kpair.setPassphrase(passphrase);
			
			String path = System.getProperty("java.io.tmpdir");
			String fullPath = path + "/" + UUID.randomUUID().toString();

			File file = new File(fullPath);
			File file1 = new File(fullPath + ".pub");

			kpair.writePrivateKey(fullPath);
			kpair.writePublicKey(fullPath + ".pub", "");
			
			byte[] encoded = Files.readAllBytes(Paths.get(fullPath));
			byte[] encoded1 = Files.readAllBytes(Paths.get(fullPath + ".pub"));
			

			
			sshpojo.setAlgo(algo);
			sshpojo.setKeySize(keySize);
			sshpojo.setPrivateKey(new String(encoded));
			sshpojo.setPublicKey(new String(encoded1));
			sshpojo.setFingerprint(kpair.getFingerPrint() );

			kpair.dispose();
			
			if(file!=null)
			{
				try {
					file.delete();
				} catch (Exception e) {
					
				}
			}
			
			if(file1!=null)
			{
				try {
					file1.delete();
				} catch (Exception e) {
					
				}
			}
		}
		
		return sshpojo;

	}


	public static void main(String[] args) throws Exception {
		// Generate and print an Ed25519 keypair using system ssh-keygen for testing
		sshpojo ed = generateEd25519WithSshKeygen("test-ed25519", "213");
		System.out.println("Algorithm: " + ed.getAlgo());
		System.out.println("Public key (OpenSSH):\n" + ed.getPublicKey());
		System.out.println("Private key (OpenSSH/PEM):\n" + ed.getPrivateKey());
	}

    // Option B: Generate Ed25519 via JDK (Java 15+) and output OpenSSH public key and PKCS#8 private key
    public static sshpojo generateEd25519Keypair(String comment) throws Exception {
        java.security.KeyPairGenerator kpg;
        try {
            kpg = java.security.KeyPairGenerator.getInstance("Ed25519");
        } catch (Exception e) {
            throw new UnsupportedOperationException("Ed25519 not available in current JRE providers. Requires Java 15+ or a provider with Ed25519.");
        }
        java.security.KeyPair kp = kpg.generateKeyPair();

        byte[] pubDer = kp.getPublic().getEncoded(); // X.509 SubjectPublicKeyInfo
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubDer));
        byte[] rawPub = spki.getPublicKeyData().getBytes(); // 32-byte Ed25519 public key

        String opensshPub = toOpenSSHEd25519Public(rawPub, comment);

        // Private in PKCS#8 PEM
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        String pemPriv = toPkcs8Pem(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pkcs8)));

        sshpojo out = new sshpojo();
        out.setAlgo("ED25519");
        out.setKeySize(256);
        out.setPublicKey(opensshPub);
        out.setPrivateKey(pemPriv);
        out.setFingerprint(sha256Fingerprint(rawPub));
        return out;
    }

    private static String toOpenSSHEd25519Public(byte[] rawPubKey, String comment) throws Exception {
        byte[] key = rawPubKey; // 32 bytes
        byte[] type = "ssh-ed25519".getBytes("UTF-8");
        byte[] payload = concat(sshString(type), sshString(key));
        String b64 = java.util.Base64.getEncoder().encodeToString(payload);
        String c = (comment == null) ? "" : comment;
        return "ssh-ed25519 " + b64 + (c.isEmpty() ? "" : (" " + c));
    }

    private static String toPkcs8Pem(PrivateKeyInfo p8) throws Exception {
        byte[] der = p8.getEncoded();
        String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    private static byte[] sshString(byte[] data) {
        int len = data.length;
        return concat(new byte[] { (byte)(len >>> 24), (byte)(len >>> 16), (byte)(len >>> 8), (byte)len }, data);
    }

    private static byte[] concat(byte[]... arrs) {
        int total = 0;
        for (byte[] a : arrs) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, pos, a.length); pos += a.length; }
        return out;
    }

    private static String sha256Fingerprint(byte[] pub) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        String type = "ssh-ed25519";
        byte[] payload = concat(sshString(type.getBytes("UTF-8")), sshString(pub));
        String b64 = java.util.Base64.getEncoder().encodeToString(md.digest(payload));
        return "SHA256:" + b64;
    }

    // Use system ssh-keygen to generate an Ed25519 keypair. Returns keys as strings.
    public static sshpojo generateEd25519WithSshKeygen(String comment, String passphrase) throws Exception {
        String path = System.getProperty("java.io.tmpdir");
        String base = path + "/" + UUID.randomUUID().toString();
        File priv = new File(base);
        File pub = new File(base + ".pub");

        String c = (comment == null) ? "" : comment;
        String p = (passphrase == null) ? "" : passphrase;

        ProcessBuilder pb = new ProcessBuilder(
                "ssh-keygen",
                "-t", "ed25519",
                "-f", base,
                "-C", c,
                "-N", p,
                "-q"
        );
        Process pr;
        try {
            pr = pb.start();
        } catch (Exception e) {
            throw new UnsupportedOperationException("ssh-keygen not found in PATH. Please install OpenSSH or add it to PATH.");
        }
        try {
            // wait up to 10 seconds
            boolean finished = pr.waitFor(10, TimeUnit.SECONDS);
            if (!finished) {
                pr.destroy();
            }
            if (!finished || pr.exitValue() != 0) {
                String err;
                try {
                    err = new String(readFully(pr.getErrorStream()), java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ex) {
                    err = "(unable to read error stream)";
                }
                throw new RuntimeException("ssh-keygen failed: " + err);
            }

            byte[] privBytes = Files.readAllBytes(Paths.get(base));
            byte[] pubBytes = Files.readAllBytes(Paths.get(base + ".pub"));
            String pubStr = new String(pubBytes, java.nio.charset.StandardCharsets.UTF_8).trim();
            String privStr = new String(privBytes, java.nio.charset.StandardCharsets.UTF_8).trim();

            // Compute SHA256 fingerprint of the OpenSSH public key line
            String fp = fingerprintFromOpenSSHPub(pubStr);

            sshpojo out = new sshpojo();
            out.setAlgo("ED25519");
            out.setKeySize(256);
            out.setPublicKey(pubStr);
            out.setPrivateKey(privStr);
            out.setFingerprint(fp);
            return out;
        } finally {
            // Always remove generated files
            closeQuietly(pr.getInputStream());
            closeQuietly(pr.getErrorStream());
            closeQuietly(pr.getOutputStream());
            cleanupFiles(priv, pub);
        }
    }

    private static String fingerprintFromOpenSSHPub(String pubLine) throws Exception {
        if (pubLine == null) return null;
        String[] parts = pubLine.trim().split("\\s+");
        if (parts.length < 2) return null;
        byte[] payload = java.util.Base64.getDecoder().decode(parts[1]);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        String b64 = java.util.Base64.getEncoder().encodeToString(md.digest(payload));
        return "SHA256:" + b64;
    }

    private static void cleanupFiles(File... files) {
        for (File f : files) {
            if (f != null) {
                try { f.delete(); } catch (Exception ignored) {}
            }
        }
    }

    private static byte[] readFully(java.io.InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int r;
        while ((r = in.read(buf)) != -1) {
            bos.write(buf, 0, r);
        }
        return bos.toByteArray();
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (Exception ignored) {}
    }

}
