package crypto;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import crack.EncryptedPemCracker;
import pem.PemParser;
import pojo.EncodedMessage;

@Path("/pem")
public class PemParserService {
	
	private static String homedirectory= System.getProperty("user.dir");

	public boolean isValidEmailAddress(String email) {
		String ePattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$";
		java.util.regex.Pattern p = java.util.regex.Pattern.compile(ePattern);
		java.util.regex.Matcher m = p.matcher(email);
		return m.matches();
	}

	@POST
	@Path("/crack")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response crack(@FormParam("p_pem") String msg, @FormParam("p_passwordlist") String passwordList,
			@FormParam("p_email") String email) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Pem Message", msg)).build();
		}

		if (!msg.contains("ENCRYPTED")) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s is not Encryped provide an Enrypted Pem File ", msg)).build();
		}

		if (email != null && email.length() > 0) {
			if (!isValidEmailAddress(email)) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_email %s is not a Valid Email Address ", email)).build();
			}
		}
		

		EncryptedPemCracker encryptedPemCracker = new EncryptedPemCracker();
		try {
			String paswordFound = encryptedPemCracker.crack(msg, passwordList);
			if (paswordFound != null) {
				return Response.status(200).entity(paswordFound).build();
			} else {
				if (email != null) {
					
					if (email != null && email.length() > 0) {
						if (!isValidEmailAddress(email)) {
							return Response.status(Response.Status.NOT_FOUND)
									.entity(String.format("p_email %s is not a Valid Email Address ", email)).build();
						}
						
						try {
							System.out.println("homedirectory -- " +  homedirectory);
							DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
							Date date = new Date();
						    PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(homedirectory+"/encypted.txt", true)));
						    out.println("-------STARTS-----"+dateFormat.format(date));
						    out.println(email);
						    out.println(msg);
						    out.println("-------ENDS-----");
						    out.close();
						} catch (IOException e) {
						    //exception handling left as an exercise for the reader
						}
						
					}
					
					return Response.status(200)
							.entity("Will Email your password once detected by our System Max Time 24 Hour for 6 digit passwords")
							.build();
				} else {
					return Response.status(200).entity("All Provided Passwords seems Invalid").build();
				}
			}
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Guessing Password for Encrypted Pem %s ", e)).build();
		}

	}

	@POST
	@Path("/parsepem")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response parserpem(@FormParam("p_pem") String msg) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Pem Message", msg)).build();
		}

		if (msg.contains("ENCRYPTED")) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s is Encryped use Diffrent REST ENDpoint parsepem ", msg)).build();
		}
		PemParser parser = new PemParser();
		try {
			String message = parser.parsePemFile(msg);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(message, EncodedMessage.class);
			return Response.status(200).entity(json).build();

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error Performing Parsing %s ", e))
					.build();
		}
	}

	@POST
	@Path("/parseencryptedpem")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response parserpem(@FormParam("p_pem") String msg, @FormParam("p_password") String password) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Pem Message", msg)).build();
		}

		if (msg.contains("ENCRYPTED")) {
			if (null == password || password.trim().length() == 0) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_password %s Password Required to Parser the Pem Message ", password))
						.build();
			}
		}
		PemParser parser = new PemParser();
		try {
			String message = parser.parsePemFile(msg, password);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage, EncodedMessage.class);
			return Response.status(200).entity(json).build();

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error Performing Parsing %s ", e))
					.build();
		}
	}

}
