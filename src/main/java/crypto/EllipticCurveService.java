package crypto;

import java.util.Enumeration;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.google.gson.Gson;

import ec.EllipticCurve;
import pojo.EncodedMessage;
import pojo.ecpojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */
@Path("/ec")
public class EllipticCurveService {

	@GET
	@Path("/getecparams")
	@Produces({ "application/json" })
	public Response getAllEcParamas() {
		Gson gson = new Gson();
		List<String> string = EllipticCurve.getAllECNamedCurveName();
		String json = gson.toJson(string);
		return Response.status(200).entity(json).build();
	}

	@GET
	@Path("/generatekp/{p_ecname}")
	@Produces({ "application/json" })
	public Response generateKeyABPairSharedSecret(@PathParam("p_ecname") String name) {

		if (name == null || name.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Empty ecparamname Name", name)).build();
		}

		name = name.trim();
		boolean ecParamValid = false;
		Enumeration<String> e = ECNamedCurveTable.getNames();
		while (e.hasMoreElements()) {
			String param = e.nextElement();
			if (param.equals(name)) {
				ecParamValid = true;
				break;
			}
		}

		if (ecParamValid) {
			EllipticCurve curve = new EllipticCurve();
			ecpojo ecpojo = curve.generateKeyABPairSharedSecret(name);
			Gson gson = new Gson();
			String json = gson.toJson(ecpojo);
			return Response.status(200).entity(json).build();
		} else {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s not a Valid EC_Param Name", name)).build();
		}
	}

	@POST
	@Path("/ecencryptdecrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptDecryptMsg(@FormParam("p_msg") String msg, @FormParam("p_publicKey") String publicKey,
			@FormParam("p_privatekey") String privatekey, @FormParam("p_iv") String intialvector,
			@FormParam("p_encryptDecrypt") String encryptDecrypt) {
		


		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (publicKey == null || publicKey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Public Key is EMpty or Null", publicKey)).build();
		}

		if (privatekey == null || privatekey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Private Key is EMpty or Null", privatekey)).build();
		}
		
		if (encryptDecrypt == null || encryptDecrypt.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s encryptDecrypt Key is EMpty or Null Accepted Value (encrypt,decrypt)",
							encryptDecrypt))
					.build();
		}
		
		encryptDecrypt = encryptDecrypt.trim();
		
		if (!"encrypt".equals(encryptDecrypt)) {
			if(!"decrypt".equals(encryptDecrypt))
			{
			System.out.println("Here--C" + encryptDecrypt);
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s encryptDecrypt Key is Not Valid Accepted Value (encrypt,decrypt)",
							encryptDecrypt))
					.build();
			}
		}

	
		if (!publicKey.contains("BEGIN PUBLIC KEY") && !publicKey.contains("END PUBLIC KEY"))

		{

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s does not have Valid EC Public Key it should start with \n -----BEGIN PGP PUBLIC KEY BLOCK----- \n and ends with \n -----END PGP PUBLIC KEY BLOCK----- \n",
							publicKey))
					.build();
		}
		

		if (!privatekey.contains("BEGIN EC PRIVATE KEY") && !privatekey.contains("END EC PRIVATE KEY"))

		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"param1 %s does not have Valid EC Private Key it should start with \n -----BEGIN EC PRIVATE KEY----- \n and ends with \n -----END EC PRIVATE KEY----- \n",
							publicKey))
					.build();
		}

		if (intialvector == null || intialvector.isEmpty()) {
			intialvector = null;
			
			if("decrypt".equals(encryptDecrypt))
			{
				
				return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error Performing Original InitialVectore needed which is Used for Decryption %s ", encryptDecrypt))
						.build();
			}
		}
		String algo = "AES/GCM/NoPadding";
		if ("encrypt".equals(encryptDecrypt) || "decrypt".equals(encryptDecrypt)) {
			EllipticCurve curve = new EllipticCurve();
			try {
				EncodedMessage m = curve.encryptDecryptMessage(privatekey, publicKey, msg, algo, intialvector,
						encryptDecrypt);

				Gson gson = new Gson();

				String json = gson.toJson(m);
				return Response.status(200).entity(json).build();
			} catch (Exception e) {
				e.printStackTrace();
				return Response.status(Response.Status.NOT_FOUND).entity(String.format("Error Performing %s ", e))
						.build();
			}
		}
		
		return Response.status(Response.Status.NOT_FOUND).entity(String.format("Can't Process the Message ..."))
						.build();

	}

}
