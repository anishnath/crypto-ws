package crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.helpers.DefaultHandler;

import com.google.gson.Gson;

import pojo.samlpojo;
import pojo.sshpojo;
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

		if (null == publickey  || publickey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_key %s x509.cert needed", publickey)).build();
		}

		if ( null== privateKey || privateKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_privkey %s Private Key needed for Signature generation ", privateKey))
					.build();
		}

		if ( null == relayState  ||  relayState.trim().length() == 0) {
			relayState = null;
		}
		
		if ( null == relayState  ||  relayState.trim().length() == 0) {
			relayState = null;
		}

		if ( null == xml  ||  xml.trim().length() == 0) {
			return Response
					.status(Response.Status.NOT_FOUND).entity(String
							.format("p_xml %s Please Input an XML to be Signed ", algo))
					.build();
		}
		
		try {
			 SAXParserFactory spf = SAXParserFactory.newInstance();
             spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
             SAXParser saxParser =spf.newSAXParser();
             InputStream stream = new ByteArrayInputStream(xml.getBytes("UTF-8"));
             saxParser.parse(stream,new DefaultHandler());
        } catch (Exception e) {
        	return Response
					.status(Response.Status.NOT_FOUND).entity(String
							.format("p_xml %s Invalid  XML  ", e))
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

}
