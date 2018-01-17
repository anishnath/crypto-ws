package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cipher.EncryptDecrypt;
import pbe.PBEEncryptDecrypt;
import pojo.EncodedMessage;

@Path("/encryptdecrypt")
public class EncryptionService {
	
	

	
	
	@POST
	@Path("/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_secretkey") String secretkey, @FormParam("p_cipher") String cipherparamater) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s secretkey is EMpty or Null", secretkey)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		EncryptDecrypt encryptDecrypt  =  new EncryptDecrypt();
		
		try {
			String message = encryptDecrypt.encrypt(msg, secretkey, cipherparamater);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Encryption %s ", e)).build();
		}
		
	}
	
	
	
	
	
	
	
	@POST
	@Path("/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptMsg(@FormParam("p_msg") String msg, @FormParam("p_secretkey") String secretkey, @FormParam("p_cipher") String cipherparamater) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s secretkey is EMpty or Null", secretkey)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		EncryptDecrypt encryptDecrypt  =  new EncryptDecrypt();
		try {
			String message = encryptDecrypt.decrypt(msg, secretkey, cipherparamater);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Decryption  %s ", e)).build();
		}
		
	}

}
