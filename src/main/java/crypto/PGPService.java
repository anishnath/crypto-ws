package crypto;

import java.io.InputStream;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;
import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;

import pgp.PGPRSAKeyPairGenerator;
import pgp.VerifyAndSignedFileProcessor;
import pgp.pgppojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
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

	@POST
	@Path("/{pgpverifyfile}")
	@Produces({ "application/json" })
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	public Response verifyPGPFileSignature(@FormDataParam("file") InputStream uploadedInputStream,
			@FormDataParam("file") FormDataContentDisposition fileDetail,
			@FormDataParam("pKey") InputStream publicKey,
			@FormDataParam("pKey") FormDataContentDisposition pkeyDetails) {

		// check if all form parameters are provided
		if (uploadedInputStream == null || fileDetail == null)
			return Response.status(400).entity("Invalid form data").build();

		if (publicKey == null || pkeyDetails == null)
			return Response.status(400).entity("Public key is EMpty").build();

		String fileName = fileDetail.getFileName();
		System.out.println(fileName);
		System.out.println(publicKey);
		
		String message = VerifyAndSignedFileProcessor.verifyFile(uploadedInputStream, publicKey);
		
		return Response.status(200).entity(message).build();
		

	}

}
