package crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.helpers.DefaultHandler;

import com.google.gson.Gson;
import com.onelogin.saml2.util.Util;

import pojo.samlpojo;
import pojo.sshpojo;
import xml.SAMLHelper;
import xml.SAMLXmlProcessor;

/**
 * 
 * @author Anish Nath Demo @ https://8gwifi.org
 *
 */

@Path("/saml")
public class SAMLService {

	final String arr[] = { "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256",
			"http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512",
			"http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2009/xmldsig11#dsa-sha256",
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
			"http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			"http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			"http://www.w3.org/2001/04/xmlenc#rsa-1_5", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
			"http://www.w3.org/2000/09/xmldsig#enveloped-signature" };

	final String signatureAlgo[] = { "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
			"http://www.w3.org/2009/xmldsig11#dsa-sha256", "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	};

	@GET
	@Path("/getxmldsigalgo")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response getParam() {
		Gson gson = new Gson();
		String json = gson.toJson(arr);
		return Response.status(200).entity(json).build();

	}

	@POST
	@Path("/sign")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response sign(@FormParam("p_xml") String xml, @FormParam("p_key") String publickey,
			@FormParam("p_privkey") String privateKey, @FormParam("p_relaystate") String relayState,
			@FormParam("p_algo") String algo, @FormParam("p_password") String password) {

		if (null == publickey || publickey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_key %s x509.cert needed", publickey)).build();
		}

		if (null == privateKey || privateKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_privkey %s Private Key needed for Signature generation ", privateKey))
					.build();
		}

		if (null == relayState || relayState.trim().length() == 0) {
			relayState = null;
		}

		if (null == algo || algo.trim().length() == 0) {
			algo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
		}

		if (null == xml || xml.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_xml %s Please Input an XML to be Signed ", xml)).build();
		}

		try {
			SAXParserFactory spf = SAXParserFactory.newInstance();
			spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			SAXParser saxParser = spf.newSAXParser();
			InputStream stream = new ByteArrayInputStream(xml.getBytes("UTF-8"));
			saxParser.parse(stream, new DefaultHandler());
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("p_xml %s Invalid  XML  ", e))
					.build();

		}

		algo = algo.trim().toLowerCase();

		boolean isValidAlgo = false;

		for (int i = 0; i < arr.length; i++) {

			if (algo.equals(arr[i])) {
				isValidAlgo = true;
				break;
			}
		}

		if (!isValidAlgo) {
			Gson json = new Gson();
			return Response
					.status(Response.Status.NOT_FOUND).entity(String
							.format("p_algo %s %s XML Signatue valid algos are  ", algo, json.toJson(signatureAlgo)))
					.build();
		}

		try {

			SAMLXmlProcessor samlXmlProcessor = new SAMLXmlProcessor();
			samlpojo samlpojo = samlXmlProcessor.signNode(privateKey, publickey, xml, algo, password, relayState);
			Gson gson = new Gson();
			String json = gson.toJson(samlpojo, samlpojo.class);
			return Response.status(200).entity(json).build();

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Signing Requested XML  %s ", e)).build();
		}

	}

	@POST
	@Path("/validatesign")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response validatesign(@FormParam("p_xml") String xml, @FormParam("p_key") String publickey,
			@FormParam("p_fingerprint") String fingerprint, @FormParam("p_algo") String algo,
			@FormParam("p_xpath") String xpath) {

		if (null == publickey || publickey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_key %s x509.cert needed", publickey)).build();
		}

		if (null == xml || xml.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_xml %s Please Input an XML to be Signed ", xml)).build();
		}

		if (null == xpath || xpath.trim().length() == 0) {
			xpath = com.onelogin.saml2.util.Util.RESPONSE_SIGNATURE_XPATH;
		}

		if (xpath != null && (xpath.equalsIgnoreCase("Response"))) {
			xpath = com.onelogin.saml2.util.Util.RESPONSE_SIGNATURE_XPATH;
		} else {
			xpath = com.onelogin.saml2.util.Util.ASSERTION_SIGNATURE_XPATH;
		}

		try {
			SAXParserFactory spf = SAXParserFactory.newInstance();
			spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			SAXParser saxParser = spf.newSAXParser();
			InputStream stream = new ByteArrayInputStream(xml.getBytes("UTF-8"));
			saxParser.parse(stream, new DefaultHandler());

		} catch (Exception e) {

			try {
				// Give One more chance
				xml = Util.base64decodedInflated(xml).toString();
				SAXParserFactory spf = SAXParserFactory.newInstance();
				spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
				SAXParser saxParser = spf.newSAXParser();
				InputStream stream = new ByteArrayInputStream(xml.getBytes("UTF-8"));
				saxParser.parse(stream, new DefaultHandler());

			} catch (Exception e1) {
				return Response.status(Response.Status.NOT_FOUND).entity(String.format("p_xml %s Invalid  XML  ", e))
						.build();
			}

		}

		SAMLHelper helper = new SAMLHelper();
		try {
			boolean isValid = helper.validateSignature(xml, publickey, fingerprint, algo, xpath);
			Gson gson = new Gson();
			StringBuilder builder = new StringBuilder();
			builder.append("XPTAH=" + xpath + ",");

			if (isValid) {
				builder.append("Validation Passed ");
			} else {
				builder.append("Validation Failed ");
			}

			return Response.status(200).entity(builder.toString()).build();
		} catch (Exception e1) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Verifying Requested XML  %s ", e1)).build();
		}

	}
	
	@POST
	@Path("/base64decodedInflated")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response base64decodedInflated(@FormParam("p_xml") String xml, @FormParam("p_debug") String debug ) {
		
		if (null == xml || xml.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_xml %s Please Input an XML to to be deflated ", xml)).build();
		}

		
		boolean isXML = false;
		try {
			SAXParserFactory spf = SAXParserFactory.newInstance();
			spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			SAXParser saxParser = spf.newSAXParser();
			InputStream stream = new ByteArrayInputStream(xml.getBytes("UTF-8"));
			saxParser.parse(stream, new DefaultHandler());
			isXML = true;
		} catch (Exception e) {
			//IGNORE 
		}
		
		if(isXML)
		{
			return Response.status(400).entity("Input is an XML Nothing to deflatedBase64").build();
		}
		
		
		SAMLHelper helper = new SAMLHelper();
		try {
			String message = helper.deflatedBase64(xml);
			Gson gson = new Gson();
			return Response.status(200).entity(message).build();
		}
		catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error on deflateTobase64 %s ", e)).build();
		}
		
	}
	
	@POST
	@Path("/encode")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encode(@FormParam("p_xml") String xml) {
		
		if (null == xml || xml.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_xml %s Please Input an XML to to be encoded ", xml)).build();
		}
		
		
		SAMLHelper helper = new SAMLHelper();
		try {
			String message = helper.encodedBase64(xml);
			Gson gson = new Gson();
			return Response.status(200).entity(gson.toJson(message)).build();
		}
		catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error on encode %s ", e)).build();
		}
		
	}

}
