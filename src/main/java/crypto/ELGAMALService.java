package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cacerts.Utils;
import elgamal.elgamal;
import pojo.EncodedMessage;
import pojo.elgamlpojo;

/**
 * 
 * @author aninath
 * Demo @ https://8gwifi.org
 *
 */
@Path("/elgamal")
public class ELGAMALService {

	@GET
	@Path("/{p_keysize}")
	@Produces({ "application/json" })
	public Response generateKeyPair(@PathParam("p_keysize") String keySize) {

		int keysize = 160;
		if (keySize == null || keySize.trim().length() == 0) {
			keysize = 160;
		}

		try {
			keysize = Integer.parseInt(keySize);
		} catch (NumberFormatException e) {
			keysize = 160;
		}

		if (keysize > 512) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s Max Supported ELgamal KeySize is 512 beyond this Raise a Feature request",
							keySize))
					.build();
		}

		elgamal elgamal = new elgamal();

		try {
			elgamlpojo elgamlpojo = elgamal.generateKeys(keysize);
			Gson gson = new Gson();
			String json = gson.toJson(elgamlpojo, elgamlpojo.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error generating ELGAMAL Key pair %s ", e)).build();
		}
	}

	@POST
	@Path("/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encrypt(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
			@FormParam("p_algo") String algo) {

		String publickeyFormat = "-----BEGIN PUBLIC KEY-----\n"
				+ "MIHYMIGQBgYrDgcCAQEwgYUCQQDRny+MwGtWkuKJ/seIuCQsyNPrcNzN3Lfxaomi\n" + "-----END PUBLIC KEY-----";

		if (null == msg || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Empty msg for Encryption", msg)).build();
		}

		if (null == algo || algo.trim().length() == 0) {
			algo = "ELGAMAL";
		}

		if (null == publicKey || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s ELGAMAL Public Key required for Encryption", publicKey)).build();
		}

		if (!publicKey.contains("BEGIN PUBLIC KEY") && !publicKey.contains("END PUBLIC KEY")) {
			return Response.status(Response.Status.NOT_FOUND).entity(String
					.format("param1 %s ELGAMAL Public Key Invalid sample public key %s  ", publicKey, publickeyFormat))
					.build();
		}

		algo = algo.trim().toUpperCase();

		if (algo.equals("ELGAMAL/ECB/PKCS1PADDING") || algo.equals("ELGAMAL/NONE/NOPADDING")
				|| algo.equals("ELGAMAL/PKCS1") || algo.equals("ELGAMAL")) {

			elgamal elgamal = new elgamal();
			try {
				String encrypted = elgamal.encrypt(msg, algo, publicKey);

				EncodedMessage encodedMessage = new EncodedMessage();
				encodedMessage.setBase64Encoded(encrypted);
				encodedMessage.setHexEncoded(Utils.toHexEncoded(Utils.decodeBASE64(encrypted)));

				Gson gson = new Gson();

				String json = gson.toJson(encodedMessage);

				return Response.status(200).entity(json).build();

			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Performing ELGAMAL Encryption %s ", e)).build();
			}

		} else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s Valid ELGAMAL Algos are ELGAMAL,ELGAMAL/ECB/PKCS1PADDING,ELGAMAL/NONE/NOPADDING,ELGAMAL/PKCS1",
							algo))
					.build();
		}

	}

	@POST
	@Path("/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decrypt(@FormParam("p_msg") String msg, @FormParam("p_privatekey") String privatekey,
			@FormParam("p_algo") String algo) {

		String privateKeyFormat = "-----BEGIN PRIVATE KEY-----\n"
				+ "oSiQlwvdUADTg9B4WfvjKu2wSdU0Vp8NMtybQMDgxLaeUFLFzZvuS7O5+T7Y0MA4ikzs\n"
				+ "-----END PRIVATE KEY-----";

		if (null == msg || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Empty msg for Decryption", msg)).build();
		}

		if (null == algo || algo.trim().length() == 0) {
			algo = "ELGAMAL";
		}

		if (null == privatekey || privatekey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s ELGAMAL Private Key required for Encryption", privatekey)).build();
		}

		if (!privatekey.contains("BEGIN PRIVATE KEY") && !privatekey.contains("END PRIVATE KEY")) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s ELGAMAL Private Key Invalid sample ELGAMAL Private key %s  ",
							privatekey, privateKeyFormat))
					.build();
		}

		algo = algo.trim().toUpperCase();

		if (algo.equals("ELGAMAL/ECB/PKCS1PADDING") || algo.equals("ELGAMAL/NONE/NOPADDING")
				|| algo.equals("ELGAMAL/PKCS1") || algo.equals("ELGAMAL")) {

			elgamal elgamal = new elgamal();
			try {

				String decrypted = elgamal.decrypt(msg, algo, privatekey);
				
				EncodedMessage encodedMessage = new EncodedMessage();
				encodedMessage.setMessage(decrypted);
				
				Gson gson = new Gson();

				String json = gson.toJson(encodedMessage);

				return Response.status(200).entity(json).build();

			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Performing ELGAMAL Decryption  %s ", e)).build();
			}

		} else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s Valid ELGAMAL Algos are ELGAMAL,ELGAMAL/ECB/PKCS1PADDING,ELGAMAL/NONE/NOPADDING,ELGAMAL/PKCS1",
							algo))
					.build();
		}

	}

}
