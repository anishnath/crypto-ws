package ssh;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;

import pojo.sshpojo;

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
		
		SSHKeyGen sshKeyGen =  new SSHKeyGen();
		
		String keysize= "621";
		
		if( "512,576,640,704,768,832,896,960,1024,2048".contains(keysize) )
		{
			System.out.println("True");
		}
		else{
			System.out.println("Falsoerue");
		}
		
		try {
			for (int i = 0; i < 1; i++) {
				

				try {
					//System.out.println("Hello World!");

//					int type = com.jcraft.jsch.KeyPair.UNKNOWN;
//
//					JSch jsch = new JSch();
//
//					// For ECDSA Key Size is 256,384,
//					com.jcraft.jsch.KeyPair kpair = com.jcraft.jsch.KeyPair.genKeyPair(jsch, type, i);
//
//					kpair.setPassphrase("ANish");
//
//					String filename = "passpie_id_rsa";
//					kpair.writePrivateKey(filename);
//					kpair.writePublicKey(filename + ".pub", "");
//					System.out.println("Finger print: " + kpair.getFingerPrint() + " i==" + i);
//
//					
//					kpair.dispose();
					
					System.out.println(sshKeyGen.genKeyPair("RSA",  1024));
					System.out.println(sshKeyGen.genKeyPair("RSA", "211231" ,1024));
					
					System.out.println(sshKeyGen.genKeyPair("DSA",  1024));
					System.out.println(sshKeyGen.genKeyPair("DSA", "211231" ,1024));
					
					System.out.println(sshKeyGen.genKeyPair("ECDSA",  521));
					System.out.println(sshKeyGen.genKeyPair("ECDSA", "211231" ,521).getPrivateKey());
					
					System.out.println(sshKeyGen.genKeyPair("RSA", "8gwifi.org", 1024));
					System.out.println(sshKeyGen.genKeyPair("RSA", "211231" ,1024));
					
					System.out.println(sshKeyGen.genKeyPair("DSA",  1024));
					System.out.println(sshKeyGen.genKeyPair("DSA", "211231" ,1024));
					
					System.out.println(sshKeyGen.genKeyPair("ECDSA",  521));
					System.out.println(sshKeyGen.genKeyPair("ECDSA", "211231" ,521).getPrivateKey());
					
					
					
				} catch (Exception e) {
					
				}
			}
		} catch (Exception e) {

		}
	}

}
