package crypto;

import java.security.KeyPair;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cacerts.Utils;
import dsa.DSASigner;
import pgp.pgppojo;
import pojo.EncodedMessage;
import rsa.RSAEncryptionDecryption;
import rsa.RSAUtil;

@Path("/rsa")
public class RSAService {
	
	
	@GET
	@Path("/{p_keysize}")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey(@PathParam("p_keysize") String keysize) {

		

		int keySize = 512;
		
		if (keysize == null || keysize.trim().length() == 0) {
			keySize=512;
		}

		try {
			keySize = Integer.parseInt(keysize.trim());
		} catch (NumberFormatException e) {
			keySize=512;

		}
		
		if (keySize==512 || keySize==1024 || keySize==2048 || keySize==4096 )
		{
						
			try {
				
				KeyPair kp = RSAUtil.generateKey(keySize);
				
				String privaeKey = Utils.toPem(kp);
				String publicKey = Utils.toPem(kp.getPublic());
				
				pgppojo pgppojo = new pgppojo();
				
				pgppojo.setPubliceKey(publicKey);
				pgppojo.setPrivateKey(privaeKey);
				
				Gson gson = new Gson();

				String json = gson.toJson(pgppojo);
				return Response.status(200).entity(json).build();
			} catch (Exception e) {
				e.printStackTrace();
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("param1 %s Error Generating Keys  ", e)).build();
			}
			
		}else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"p_n %s Valid RSA key Size is 512,1024,2048,4096  ",
							keysize))
					.build();
		}
	}
	
	
	@POST
	@Path("/sign")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response signMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("FOR RSA Signing Message %s RSA private Key required", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			algo="SHA256withRSA";
		}
		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			
			
			String signature = encryptionDecryption.signMessage(publicKey, msg, algo);
			return Response.status(200).entity(signature).build();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Signature generation %s ", e)).build();
		}
	}
	
	
	@POST
	@Path("/verify")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response verifyMsg(@FormParam("p_msg") String msg, @FormParam("p_sig") String signature, @FormParam("p_key") String publicKey, 
			@FormParam("p_algo") String algo) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}
		
		if (signature == null || signature.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_sig %s does not have a Signature for Verification", msg)).build();
		}
		
		signature = signature.trim();

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("FOR RSA Signing Message %s RSA public Key is required", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			algo="SHA256withRSA";
		}
		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			
			
			boolean ret = encryptionDecryption.verifyMessage(publicKey, msg, signature, algo);
			
			String msgr = "Signature Verification Passed";
			if(!ret)
			{
				msgr = "Signature Verification Failed";
			}
			
			return Response.status(200).entity(msgr).build();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Signatire Validation %s ", e)).build();
		}
	}

	@POST
	@Path("/rsaencrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publicKey %s Empty RSA public/privateKey", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_algo %s does not have a rsa algorithm", algo)).build();
		}

		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			String message = encryptionDecryption.encrypt(publicKey, msg, algo);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setBase64Encoded(message);
			byte[] toHex = Utils.decodeBASE64(message);
			encodedMessage.setHexDecoded(Utils.toHexEncoded(toHex));

			Gson gson = new Gson();

			String json = gson.toJson(encodedMessage);
			return Response.status(200).entity(json).build();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Encryption %s ", e)).build();
		}
	}

	@POST
	@Path("/rsadecrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

	
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}

		String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
		boolean isValidMessage = false;
		if (msg.matches(pattern)) {
			isValidMessage = true;
		}
		
        if (!isValidMessage) {
            try {
                Long.parseLong(msg, 16);
                isValidMessage = true;
            } catch (NumberFormatException ex) {
                isValidMessage = false;
            }
        }

		if (!isValidMessage) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s is not Valid base64 ENcoded Message", publicKey)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publicKey %s Empty RSA public/privateKey", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_algo %s does not have a rsa algorithm", algo)).build();
		}

		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			String message = encryptionDecryption.decrypt(publicKey, msg, algo);
			Gson gson = new Gson();
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			String json = gson.toJson(encodedMessage);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Encryption %s ", e)).build();
		}
	}

}
