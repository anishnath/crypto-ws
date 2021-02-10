package crypto;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;


import cacerts.WebCerts;
import pem.CertInfo;
import pem.CertificateVerifier;
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
	@Path("/webcerts")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response getWebCerts(@FormParam("p_url") String url,@FormParam("p_port") String port) {
		
		int Port = 443;
		
		if(null == port || port.trim().length()==0)
		{
			port = "443";
		}
		
		if(null == url || url.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_url %s Please provide the url", url)).build();
		}
		
		url = url.trim();
		
		if(url.equalsIgnoreCase("::0") || url.equalsIgnoreCase("localhost") || url.startsWith("127.0") || url.equals("2130706433") ||  url.startsWith("localhost")  )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_url %s Connection Timedout", url)).build();
		}
		
		if (port != null && port.trim().length() > 0) {
			try {
				Port = Integer.valueOf(Port);
			} catch (NumberFormatException e) {
				// TODO Auto-generated catch block
				Port = 443;
			}
		}
		
		WebCerts webcerts = new WebCerts();

		try {
			List<String> certList =  webcerts.getCerts(url, Port);
			Gson gson = new Gson();
			String json = gson.toJson(certList);
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
	public Response signcsr(@FormParam("p_pem") String msg,@FormParam("p_privatekey") String password,@FormParam("p_crl") String crl,@FormParam("p_ocsp") String ocsp) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem %s does not have a Pem Message", msg)).build();
		}
		
		SignCSR parser = new SignCSR();
		PemParser parser1 = new PemParser();
		try {
			String message = parser.sign(msg, password,crl,ocsp);
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
	
	@POST
	@Path("/verifycsrcrtkey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response verify(@FormParam("p_pem1") String pem1, @FormParam("p_pem2") String pem2) {
		if(null==pem1 || pem1.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem1 %s Input CSR or CRT or RSA Key for Validation", pem1)).build();
		}
		
		pem1 = pem1.trim();
		
		if(null==pem2 || pem2.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem1 %s Input CSR or CRT or RSA Key ", pem1)).build();
		}
		
		pem2 = pem2.trim();
		
		if(pem1.equals(pem2))
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem1 and pem2 objects are equal %s", pem1)).build();
		}
		
		boolean isValid = false;
		
		if (pem1.contains("BEGIN RSA PRIVATE KEY") && pem1.contains("END RSA PRIVATE KEY")) {
			isValid = true;
		}
		
		if (pem1.contains("BEGIN CERTIFICATE REQUEST") && pem1.contains("END CERTIFICATE REQUEST")) {
			isValid = true;
		}
		
		if (pem1.contains("BEGIN CERTIFICATE") && pem1.contains("END CERTIFICATE")) {
			isValid = true;
		}
		
		if(!isValid)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem1 %s Input CSR or CRT or RSA Key is not Valid ", pem1)).build();
		}
		
		if (pem2.contains("BEGIN RSA PRIVATE KEY") && pem2.contains("END RSA PRIVATE KEY")) {
			isValid = true;
		}
		
		if (pem2.contains("BEGIN CERTIFICATE REQUEST") && pem2.contains("END CERTIFICATE REQUEST")) {
			isValid = true;
		}
		
		if (pem2.contains("BEGIN CERTIFICATE") && pem2.contains("END CERTIFICATE")) {
			isValid = true;
		}
		
		if(!isValid)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem2 %s Input CSR or CRT or RSA Key is not Valid ", pem2)).build();
		}
		
		CertificateVerifier certificateVerifier = new CertificateVerifier();
		Gson gson = new Gson();
		try {
			certpojo certpojo = certificateVerifier.verifyCertificate(pem1, pem2);
			gson = new Gson();
			String json1 = gson.toJson(certpojo,certpojo.class);
			return Response.status(200).entity(json1).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Failed to Verify %s ", e)).build();
		}
		
		
	}
}
