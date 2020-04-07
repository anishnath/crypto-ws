package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cacerts.Utils;
import mac.Hmac;
import pojo.EncodedMessage;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

@Path("/hmac")
public class HmacService {

	// enum macchoices=
	// {"PBEWithHmacSHA1","PBEWithHmacSHA384","PBEWithHmacSHA256","PBEWithHmacSHA512","HmacSHA1",}

	enum macchoices {
		PBEWithHmacSHA1, PBEWithHmacSHA384, PBEWithHmacSHA256, 
		PBEWithHmacSHA512,
		HmacSHA1, HmacSHA384, HmacSHA224, 
		HmacSHA256, HmacSHA512, HmacMD5, HMACRIPEMD128, RC2MAC, RC5MAC, IDEAMAC, HMACRIPEMD160, SKIPJACKMAC, HMACTIGER,DES,DESEDEMAC,HMACMD5,HMACMD4,HMACMD2,SKIPJACKMACCFB8,IDEAMACCFB8;
	};

	/**
	 * 
	 * @param name
	 * @param key
	 * @param algo
	 * @return HMAC String in base64 and Hext String <blockquote> Algorithm
	 *         Supported PBEWithHmacSHA1, PBEWithHmacSHA384, PBEWithHmacSHA256,
	 *         PBEWithHmacSHA512, HmacSHA1, HmacSHA384, HmacSHA224, HmacSHA256,
	 *         HmacMD5, HmacPBESHA1, HMACRIPEMD128, RC2MAC,
	 *         IDEAMAC,HMACRIPEMD160, SKIPJACKMAC, HMACTIGER </blockquote>
	 */
	@POST
	@Path("/generatehmac")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response getHMAC(@FormParam("p_msg") String name, @FormParam("p_key") String key,
			@FormParam("p_algo") String algo) {

		if (name == null || name.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid String", name)).build();
		}

		if (key == null || key.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid key", key)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid Algoritms", algo)).build();
		}

		
		
		try {
			macchoices macchoic;
			macchoic = macchoices.valueOf(algo);
			// yes
		} catch (IllegalArgumentException ex) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format(
					"param1 %s does not have a valid Algoritms Supported ALGOS[PBEWithHmacSHA1, PBEWithHmacSHA384, PBEWithHmacSHA256, PBEWithHmacSHA512, HmacSHA1,"
							+ " HmacSHA384, HmacSHA224, HmacSHA256, HmacMD5, HmacPBESHA1, "
							+ "  HMACRIPEMD128, RC2MAC, IDEAMAC,HMACRIPEMD160, " + "  SKIPJACKMAC, " + " HMACTIGER]",
					algo)).build();
		}

		if("SKIPJACKMACCFB8".equals(algo))
		{
			algo = "SKIPJACKMAC/CFB8";
		}
		
		if("IDEAMACCFB8".equals(algo))
		{
			algo = "IDEAMAC/CFB8";
		}
		
		Hmac mac = new Hmac();
		byte[] b = mac.calculateHMAC(name, key, algo);

		EncodedMessage encodedMessage = new EncodedMessage();
		encodedMessage.setBase64Encoded(Utils.toBase64Encode(b));
		encodedMessage.setHexEncoded(Utils.toHexEncoded(b));

		Gson gson = new Gson();

		String json = gson.toJson(encodedMessage);

		return Response.status(200).entity(json).build();

	}

}
