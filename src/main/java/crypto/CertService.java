package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import pem.CertInfo;
import pem.PemParser;
import pem.SelfSignGenerate;
import pem.SignCSR;
import pojo.EncodedMessage;
import pojo.certpojo;

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
		PemParser parser1 = new PemParser();
		try {
			String message = parser.sign(msg, null);
			EncodedMessage encodedMessage = new EncodedMessage();
			String base64Decoded = parser1.parsePemFile(message);
			encodedMessage.setMessage(message);
			encodedMessage.setBase64Decoded(base64Decoded);
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
		PemParser parser1 = new PemParser();
		try {
			String message = parser.sign(msg, password);
			String base64Decoded = parser1.parsePemFile(message);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			encodedMessage.setBase64Decoded(base64Decoded);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
			
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing Parsing %s ", e)).build();
		}
	}
	
	@POST
	@Path("/genselfsign")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateSelfSign(@FormParam("p_certinfo") String json,@FormParam("p_version") String version) {
		
		if(null==json || json.trim().length()==0)
		{
			String Valid_Request ="{\"hostName\":\"8gwifi\",\"company\":\"A\",\"Department\":\"DD\",\"Email\":\"zarigatongy@gmail.com\",\"City\":\"Cyit\",\"State\":\"state\",\"Country\":\"country\",\"expiry\":12,\"alt_name\":[\"Anish\",\"Nath\",\"8gwifi.org\"]}";
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_certifno %s Request Format ", Valid_Request)).build();
		}
		
		Gson gson = new Gson();
		

		CertInfo certInfo =   gson.fromJson(json, CertInfo.class);
		
		if (certInfo ==null) 
		{
			String Valid_Request ="{\"hostName\":\"8gwifi.org\",\"company\":\"A\",\"Department\":\"DD\",\"Email\":\"zarigatongy@gmail.com\",\"City\":\"Cyit\",\"State\":\"state\",\"Country\":\"country\",\"expiry\":12,\"alt_name\":[\"Anish\",\"Nath\",\"8gwifi.org\"]}";
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_certifno %s Request Format ", Valid_Request)).build();
		}
		
		if(null==certInfo.getHostName())
		{
			String Valid_Request = "{\"hostName\":\"8gwifi.org\"}";
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_certifno %sHost name required  ", Valid_Request)).build();
		}
		
		int defaultCertVersion=3;
		if(null ==version || version.trim().length()==0)
		{
			defaultCertVersion=3;
		}
		
		if("1".equals(version))
		{
			defaultCertVersion=1;
		}
		
		SelfSignGenerate generate = new SelfSignGenerate();
		try {
			certpojo certpojo = generate.generateCertificate(certInfo, defaultCertVersion);
			gson = new Gson();
			String json1 = gson.toJson(certpojo,certpojo.class);
			return Response.status(200).entity(json1).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Generating Self Sign Certificate %s ", e)).build();
		}
		
	}
	
	@POST
	@Path("/genselfsignwithprivkey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateSelfSign(@FormParam("p_certinfo") String json, @FormParam("p_privatekey") String privatekey,@FormParam("p_version") String version) {
		
		if(null==json || json.trim().length()==0)
		{
			String Valid_Request ="{\"hostName\":\"8gwifi.org\",\"company\":\"A\",\"Department\":\"DD\",\"Email\":\"zarigatongy@gmail.com\",\"City\":\"Cyit\",\"State\":\"state\",\"Country\":\"country\",\"expiry\":12,\"alt_name\":[\"Anish\",\"Nath\",\"8gwifi.org\"]}";
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_certifno %s Request Format ", Valid_Request)).build();
		}
		
		Gson gson = new Gson();
	
		
		int defaultCertVersion=3;
		if(null ==version || version.trim().length()==0)
		{
			defaultCertVersion=3;
		}
		
		if("1".equals(version))
		{
			defaultCertVersion=1;
		}
		
		if(null==privatekey || privatekey.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_privatekey %s Is Empty or Null ", privatekey)).build();
		}
		
		privatekey = privatekey.trim();
		
		if(privatekey.contains("BEGIN RSA PRIVATE KEY") && privatekey.contains("END RSA PRIVATE KEY"))
		{
			CertInfo certInfo =   gson.fromJson(json, CertInfo.class);
			
			if (certInfo ==null) 
			{
				String Valid_Request ="{\"hostName\":\"8gwifi.org\",\"company\":\"A\",\"Department\":\"DD\",\"Email\":\"zarigatongy@gmail.com\",\"City\":\"Cyit\",\"State\":\"state\",\"Country\":\"country\",\"expiry\":12,\"alt_name\":[\"Anish\",\"Nath\",\"8gwifi.org\"]}";
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_certifno %s Request Format ", Valid_Request)).build();
			}
			
			if(null==certInfo.getHostName())
			{
				String Valid_Request = "{\"hostName\":\"8gwifi.org\"}";
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_certifno %sHost name required  ", Valid_Request)).build();
			}
			
			SelfSignGenerate generate = new SelfSignGenerate();
			try {
				certpojo certpojo = generate.generateCertificate(certInfo,privatekey, defaultCertVersion);
				gson = new Gson();
				String json1 = gson.toJson(certpojo,certpojo.class);
				return Response.status(200).entity(json1).build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating Self Sign Certificate %s ", e)).build();
			}
			
		}
		else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_privatekey  %s Inavlid RSA Private Key it should start with -----BEGIN RSA PRIVATE KEY----- and ends with -----END RSA PRIVATE KEY-----  ", privatekey)).build();
		}
		
		
		
	}
}
