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
	public Response sshkeyGen(@FormParam("p_algo") String algo, @FormParam("p_passphrase") String passphrase, @FormParam("p_keysize") String keysize) {
		
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
		
		
		
		//RSA,DSA,ECDSA
		
		
		algo = algo.trim().toUpperCase();
		
		if(algo.equals("RSA") || algo.equals("DSA")  || algo.equals("ECDSA")  )
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
				sshpojo = sshKeyGen.genKeyPair(algo, passphrase, keySize);
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
					.entity(String.format("p_algo %s Supported Algos are RSA,DSA,ECDSA", passphrase)).build();			
		}
		
		

	}

}
