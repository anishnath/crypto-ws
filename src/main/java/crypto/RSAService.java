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
import pojo.EncodedMessage;
import rsa.RSAEncryptionDecryption;

@Path("/rsa")
public class RSAService {

	@POST
	@Path("/rsaencrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publicKey %s Empty RSA public/privateKey", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_algo %s does not have a rsa algorithm", algo)).build();
		}

		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			String message = encryptionDecryption.encrypt(publicKey, msg, algo);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setBase64Encoded(message);
			byte[] toHex = Utils.decodeBASE64(message);
			encodedMessage.setHexDecoded(Utils.toHexEncoded(toHex));

			Gson gson = new Gson();

			String json = gson.toJson(encodedMessage);
			return Response.status(200).entity(json).build();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Encryption %s ", e)).build();
		}
	}

	@POST
	@Path("/rsadecrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

	
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s does not have a Message", msg)).build();
		}

		String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
		boolean isValidMessage = false;
		if (msg.matches(pattern)) {
			isValidMessage = true;
		}
		
        if (!isValidMessage) {
            try {
                Long.parseLong(msg, 16);
                isValidMessage = true;
            } catch (NumberFormatException ex) {
                isValidMessage = false;
            }
        }

		if (!isValidMessage) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_msg %s is not Valid base64 ENcoded Message", publicKey)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publicKey %s Empty RSA public/privateKey", publicKey)).build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_algo %s does not have a rsa algorithm", algo)).build();
		}

		RSAEncryptionDecryption encryptionDecryption = new RSAEncryptionDecryption();
		try {
			String message = encryptionDecryption.decrypt(publicKey, msg, algo);
			Gson gson = new Gson();
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			String json = gson.toJson(encodedMessage);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing RSA Encryption %s ", e)).build();
		}
	}

}
