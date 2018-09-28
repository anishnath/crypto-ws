package crypto;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;
import com.nimbusds.jose.util.JSONObjectUtils;

import jwk.JwkKeyGenerator;
import net.minidev.json.JSONObject;
import pojo.jwkpojo;

@Path("/jwk")
public class JWKService {

	final static Map<String, String> jwKeymap = new HashMap<String, String>();

	static {
		jwKeymap.put("1", "2048,encryption,rsa");
		jwKeymap.put("2", "4096,encryption,rsa");
		jwKeymap.put("3", "2048,sig,rsa");
		jwKeymap.put("4", "4096,sig,rsa");
		jwKeymap.put("5", "P-256,ec");
		jwKeymap.put("6", "P-256K,ec");
		jwKeymap.put("7", "P-384,ec");
		jwKeymap.put("8", "P-521,ec");
		jwKeymap.put("9", "Ed25519,ok");
		jwKeymap.put("10", "X25519,ok");
		jwKeymap.put("11", "HS256,os");
		jwKeymap.put("12", "HS384,os");
		jwKeymap.put("13", "HS512,os");
		jwKeymap.put("14", "A128GCM,os");
		jwKeymap.put("15", "A192GCM,os");
		jwKeymap.put("16", "A256GCM,os");
		jwKeymap.put("17", "A128CBC_HS256,os");

	}
	
	
	@POST
	@Path("/convertpemtojwk")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response convertPEMtoJWK(@FormParam("p_param") String msg) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}
		
		msg=msg.trim();
		
		if (msg.contains("---") && msg.contains("BEGIN") && msg.contains("END")) {
			
			JwkKeyGenerator generator = new JwkKeyGenerator();
			
			try {
				return Response.status(200).entity(generator.convertPEMtoJWK(msg)).build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error in conversion %s ", e)).build();
			}
			
		}
		
		else {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s is not RSA format", msg))
					.build();
		}
		
		
	}

	@POST
	@Path("/convertjwktopem")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response convertJWKtoRSA(@FormParam("p_param") String msg) {

		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		msg = msg.trim();

		if (msg.contains("kty") && msg.contains("{") && msg.contains("}")) {

			try {
				JSONObject jsonObject = JSONObjectUtils.parse(msg);

				String kty = JSONObjectUtils.getString(jsonObject, "kty");

				if ("rsa".equalsIgnoreCase(kty) || "ec".equalsIgnoreCase(kty)) {

					JwkKeyGenerator generator = new JwkKeyGenerator();
					try {
						jwkpojo message = generator.convertJWKtoPEM(msg,kty);
						Gson gson = new Gson();
						String json = gson.toJson(message, jwkpojo.class);
						return Response.status(200).entity(json).build();
					} catch (Exception e) {
						return Response.status(Response.Status.NOT_FOUND)
								.entity(String.format("Error in conversion %s ", e)).build();
					}
				}
				else {
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("only kty rsa and ec supported  %s "))
							.build();
				}

			} catch (ParseException e1) {
				return Response.status(Response.Status.NOT_FOUND).entity(String.format("Not a Valid JWK  %s ", e1))
						.build();
			}

		} else {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s is not RSA JWK", msg))
					.build();
		}

	}

	@POST
	@Path("/generatekey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey(@FormParam("p_param") String msg) {

		JwkKeyGenerator generator = new JwkKeyGenerator();

		if (msg == null || msg.trim().length() == 0) {

			try {
				return Response.status(200).entity(generator.generateRSAJWKKey(1024, "encryption")).build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}
		}

		msg = msg.trim();
		if (jwKeymap.get(msg) == null) {
			try {
				return Response.status(200).entity(generator.generateRSAJWKKey(1024, "encryption")).build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}
		}

		String p1 = jwKeymap.get(msg);

		if (p1.contains("rsa")) {
			try {
				return Response.status(200)
						.entity(generator.generateRSAJWKKey(Integer.valueOf(p1.substring(0, p1.indexOf(","))),
								p1.substring(p1.indexOf(",") + 1, p1.lastIndexOf(","))))
						.build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}

		}

		if (p1.contains("ec")) {
			try {
				return Response.status(200).entity(generator.generateECJWKKey(p1.substring(0, p1.indexOf(","))))
						.build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}

		}

		if (p1.contains("os")) {
			try {
				return Response.status(200).entity(generator.generateOctetSequenceKey(p1.substring(0, p1.indexOf(","))))
						.build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}

		}

		if (p1.contains("ok")) {
			try {
				return Response.status(200).entity(generator.generateOctetKey(p1.substring(0, p1.indexOf(","))))
						.build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Generating JWK Key %s ", e)).build();
			}

		}

		return null;

	}

}
