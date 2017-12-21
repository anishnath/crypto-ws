package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import pem.PemParser;
import pojo.EncodedMessage;

@Path("/pem")
public class PemParserService {
	
	@POST
	@Path("/parsepem")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response parserpem(@FormParam("p_pem") String msg) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Pem Message", msg)).build();
		}
		
		if(msg.contains("ENCRYPTED"))
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s is Encryped use Diffrent REST ENDpoint parsepem ", msg)).build();
		}
		PemParser parser = new PemParser();
		try {
			String message = parser.parsePemFile(msg);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(message,EncodedMessage.class);
			return Response.status(200).entity(json).build();
			
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing Parsing %s ", e)).build();
		}
	}
	
	@POST
	@Path("/parseencryptedpem")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response parserpem(@FormParam("p_pem") String msg,@FormParam("p_password") String password) {
		

		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Pem Message", msg)).build();
		}
		
		if(msg.contains("ENCRYPTED"))
		{
			if(null==password || password.trim().length()==0)
			{
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_password %s Password Required to Parser the Pem Message ", password)).build();
			}
		}
		PemParser parser = new PemParser();
		try {
			String message = parser.parsePemFile(msg,password);
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
