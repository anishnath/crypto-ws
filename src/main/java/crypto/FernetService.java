package crypto;

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

import fernet.FernetEncryption;
import pojo.fernetpojo;

@Path("/fernet")
public class FernetService {

	@GET
	@Path("/genkey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey() {
		FernetEncryption encryption = new FernetEncryption();
		String key = encryption.generateKey();
		fernetpojo fernetpojo = new fernetpojo();
		fernetpojo.setKey(key);
		Gson gson = new Gson();
		String json = gson.toJson(fernetpojo);
		return Response.status(200).entity(json).build();
	}

	@POST
	@Path("/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_secretkey") String secretkey) {

		FernetEncryption encryption = new FernetEncryption();

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			secretkey = encryption.generateKey();
		}

		try {
			fernetpojo fernetpojo = encryption.encrypt(secretkey, msg);
			fernetpojo.setKey(secretkey);
			Gson gson = new Gson();
			String json = gson.toJson(fernetpojo);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error in Encryption %s ", e))
					.build();
		}

	}
	
	@POST
	@Path("/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptMsg(@FormParam("p_ftoken") String token, @FormParam("p_secretkey") String secretkey) {

		FernetEncryption encryption = new FernetEncryption();

		if (token == null || token.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty Ciphertext", token)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty key", secretkey)).build();
		}

		try {
			String decrypt = encryption.dcrypt(secretkey, token);
			fernetpojo fernetpojo = new pojo.fernetpojo();
			fernetpojo.setMsg(decrypt);
			Gson gson = new Gson();
			String json = gson.toJson(fernetpojo);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error in Decryption %s ", e))
					.build();
		}

	}

}
