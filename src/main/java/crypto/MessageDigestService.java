package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cipher.MessageDigestCalc;
import pojo.EncodedMessage;

/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

@Path("/md")
public class MessageDigestService {
	
	@POST
	@Path("/generate")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateDigest(@FormParam("p_msg") String msg, @FormParam("p_cipher") String cipherparamater) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		MessageDigestCalc calc = new MessageDigestCalc();
		cipherparamater=cipherparamater.trim();
		try {
			EncodedMessage message = calc.calculateMessageDigest(cipherparamater, msg);
			Gson gson = new Gson();
			String json = gson.toJson(message,EncodedMessage.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Encryption %s ", e)).build();
		}
		
	}

}
