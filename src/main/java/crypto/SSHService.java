package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import pojo.sshpojo;
import ssh.SSHKeyGen;
import ssh.SSHKeyConvert;

/**
 * 
 * @author Anish Nath
 * Demo @ https://8gwifi.org
 *
 */

@Path("/ssh")
public class SSHService {
	
	@POST
	@Path("/keygen")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response sshkeyGen(@FormParam("p_algo") String algo,
	                          @FormParam("p_passphrase") String passphrase,
	                          @FormParam("p_keysize") String keysize,
	                          @FormParam("p_include_ppk") String includePpk) {
		
		if (algo == null || algo.trim().length() == 0) {
			algo="RSA";
		}
		
		if(passphrase!=null && passphrase.trim().length()>20)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_passphrase %s password length should be less than 20", passphrase)).build();
		}
		
		int keySize=2048;
		if(keysize == null || keysize.trim().length()==0)
		{
			keySize=2048 ;
		}
		
		// 256
		// 384
		//521
		
		
		try { 
			keySize= Integer.parseInt(keysize); 
	    } catch(Exception e) { 
	    	keySize=2048 ;
	    }
		
		
		
        //RSA,DSA,ECDSA,ED25519
		
		
		algo = algo.trim().toUpperCase();
		
        if(algo.equals("RSA") || algo.equals("DSA")  || algo.equals("ECDSA") || algo.equals("ED25519") )
        {

            if(algo.equals("ECDSA"))
            {
                if( keySize==256 || keySize==384 || keySize==521  )
				{
					//DO Nothing
				}
				else{
					return Response.status(Response.Status.NOT_FOUND)
							.entity(String.format("p_keysize %s valid Key size for  ECDSA is (256,384,521)    ", keysize)).build();
				}
			}
			if(algo.equals("DSA"))
			{
				if( "512,576,640,704,768,832,896,960,1024,2048".contains(keysize)  )
				{
					//DO Nothing
				}
				else{
					return Response.status(Response.Status.NOT_FOUND)
							.entity(String.format("p_keysize %s valid Key size for  DSA is (512,576,640,704,768,832,896,960,1024,2048)   ", keysize)).build();
				}
			}
			
            SSHKeyGen sshKeyGen =  new SSHKeyGen();
            sshpojo sshpojo = new sshpojo();
            try {
                if (algo.equals("ED25519")) {
                    // Use system ssh-keygen for Ed25519
                    sshpojo = SSHKeyGen.generateEd25519WithSshKeygen("", passphrase);
                } else {
                    sshpojo = sshKeyGen.genKeyPair(algo, passphrase, keySize);
                }

                // Optional: also produce a PuTTY .ppk version of the same key.
                // Same passphrase carries through; failure is non-fatal — the OpenSSH
                // key is still returned and the UI can surface a hint to the user.
                if ("true".equalsIgnoreCase(includePpk) && sshpojo.getPrivateKey() != null) {
                    try {
                        String ppk = SSHKeyConvert.toPpk(sshpojo.getPrivateKey(), passphrase);
                        sshpojo.setPrivateKeyPpk(ppk);
                    } catch (SSHKeyConvert.KeyConvertException kce) {
                        // Log and continue without ppk — caller still gets OpenSSH key.
                        System.err.println("[SSHService] PPK conversion failed: " + kce.getMessage());
                    }
                }

                Gson gson = new Gson();
                String json = gson.toJson(sshpojo,sshpojo.class);
                return Response.status(200).entity(json).build();
            } catch (Exception e) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(String.format("Error generating SSH Keypait %s ", e)).build();
            }
			
		}
		else {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(String.format("p_algo %s Supported Algos are RSA, DSA, ECDSA, ED25519", passphrase)).build();
        }



	}

	/**
	 * Convert a user-supplied private key (PKCS#1 PEM or OpenSSH-format) to PuTTY .ppk.
	 * Standalone endpoint for the "I already have a key, give me a .ppk" UI tab.
	 *
	 * @param privateKey  armored private key text the user pasted
	 * @param passphrase  passphrase the input key is encrypted with, or empty if unencrypted
	 * @return JSON {"privateKeyPpk": "..."} on success, plain error text otherwise
	 */
	@POST
	@Path("/convert")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response sshConvert(@FormParam("p_private_key") String privateKey,
	                           @FormParam("p_passphrase") String passphrase) {

		if (privateKey == null || privateKey.trim().isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity("p_private_key is required (paste an OpenSSH or PEM-encoded private key)")
					.build();
		}
		if (passphrase != null && passphrase.length() > 256) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity("p_passphrase too long (max 256 chars)")
					.build();
		}

		try {
			String ppk = SSHKeyConvert.toPpk(privateKey, passphrase);
			sshpojo out = new sshpojo();
			out.setPrivateKeyPpk(ppk);
			Gson gson = new Gson();
			return Response.status(200).entity(gson.toJson(out, sshpojo.class)).build();
		} catch (SSHKeyConvert.KeyConvertException kce) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(kce.getMessage())
					.build();
		}
	}

}
