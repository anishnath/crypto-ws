package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import pem.SignCSR;
import pojo.EncodedMessage;

@Path("/certs")
public class CertService {
	
	@POST
	@Path("/signcsr")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response signcsr(@FormParam("p_pem") String msg) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s does not have a Pem Message", msg)).build();
		}

		SignCSR parser = new SignCSR();
		try {
			String message = parser.sign(msg, null);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
			
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing Parsing %s ", e)).build();
		}
	}
	
	@POST
	@Path("/signcsrprivkey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response signcsr(@FormParam("p_pem") String msg,@FormParam("p_privatekey") String password) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s does not have a Pem Message", msg)).build();
		}
		
		SignCSR parser = new SignCSR();
		try {
			String message = parser.sign(msg, password);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
			
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing Parsing %s ", e)).build();
		}
	}
}
