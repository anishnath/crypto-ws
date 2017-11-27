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

import pgp.PGPRSAKeyPairGenerator;
import pgp.pgppojo;

/**
 * 
 * @author Anish Nath 
 * For Demo Visit https://8gwifi.org
 *
 */

@Path("/pgp")
public class PGPService {

	@POST
	@Path("/{pgpkeygen}")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response getKeyPair(@FormParam("p_keysize") String keysize, @FormParam("p_identity") String identity,
			@FormParam("p_passpharse") String passPhrase, @FormParam("p_algo") String algo) {

		if (identity == null || identity.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid Identity Name", identity)).build();
		}

		if (passPhrase == null || passPhrase.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid Passphase it's empty or null", passPhrase))
					.build();
		}

		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid Algorithm", algo)).build();
		}

		int ksize = 1024;
		try {
			ksize = Integer.parseInt(keysize);
			if (ksize > 4098) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("param1 %s does not have a valid KeySize", keysize)).build();
			}
		} catch (NumberFormatException nfe) {
			ksize = 1024;
		}

		if ("BLOWFISH".equals(algo) || "AES_256".equals(algo) || "AES_192".equals(algo) || "AES_128".equals(algo)
				|| "BLOWFISH".equals(algo) || "CAST5".equals(algo) || "TWOFISH".equals(algo)
				|| "TRIPLE_DES".equals(algo)) {

			PGPRSAKeyPairGenerator generator = new PGPRSAKeyPairGenerator(ksize);
			pgppojo pgpp = null;
			try {
				pgpp = generator.genKeyPair(identity, passPhrase.toCharArray(), algo);
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("param1 %s Error Generating Keys  ", pgpp.getErrorMessage())).build();
			}

			Gson gson = new Gson();

			String json = gson.toJson(pgpp);
			return Response.status(200).entity(json).build();

		} else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s does not have a valid algorithm", algo)).build();

		}

	}

}
