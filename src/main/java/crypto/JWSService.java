package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import jwk.JWS;
import pojo.jwkpojo;
import pojo.jwspojo;

@Path("/jws")
public class JWSService {
	
	@POST
	@Path("/generatekey")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey(@FormParam("p_algo") String algo,@FormParam("p_payload") String payload) {
		
		if (algo == null || algo.trim().length() == 0) {
			algo="HS256";
		}
		
		algo=algo.trim().toUpperCase();
		
		if (payload == null || payload.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty payload", payload)).build();
		}
		
		String[] arr = new String[]{"HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"};
		boolean isValidAlgo=false;
		for (int i = 0; i < arr.length; i++) {
			if(algo.equals(arr[i]))
			{
				isValidAlgo = true;
				break;
			}
		}
		if(isValidAlgo)
		{
			JWS jws = new JWS();
			try {
				jwspojo message = jws.generateKey(algo, payload);
				Gson gson = new Gson();
				String json = gson.toJson(message, jwspojo.class);
				return Response.status(200).entity(json).build();
			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error in Generating JWS key %s ", e)).build();
			}
		}else{
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Invalid JWS Algo", algo)).build();
		}
	}
	
	@POST
	@Path("/parse")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response parse(@FormParam("p_serialzed") String serialzed ) {
		
		if (serialzed == null || serialzed.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s JWS Object is empty", serialzed)).build();
		}
		
		try {
			JWS jws = new JWS();
			jwspojo jwspojo = jws.parserJWSObject(serialzed);
			Gson gson = new Gson();
			String json = gson.toJson(jwspojo, jwspojo.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Signing %s ", e)).build();
		}
	}
	
	@POST
	@Path("/verify")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response verify(@FormParam("p_sharedsecret") String sharedsecret, @FormParam("p_serialized") String serialized, @FormParam("p_publickey") String publickey) {
		

		
		if (serialized == null || serialized.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty serialized", serialized)).build();
		}
		
		JWS jws = new JWS();
		
		try{
		boolean isValid = jws.verifySignature(sharedsecret, serialized, publickey);
		
		String msg = "VALID";
		if(!isValid)
		{
			msg = "INVALID";
		}
		return Response.status(200).entity(msg).build();
		
		}catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Verifying %s ", e)).build();
		}
		
		
		
	}
	
	@POST
	@Path("/sign")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey(@FormParam("p_algo") String algo,@FormParam("p_payload") String payload, @FormParam("p_sharedsecret") String sharedsecret, @FormParam("p_key") String key ) {
		
		if (payload == null || payload.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty payload", payload)).build();
		}
		
		if (algo == null || algo.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty JMW Algorithm", algo)).build();
		}
		
		String[] arr = new String[]{"HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"};
		boolean isValidAlgo=false;
		for (int i = 0; i < arr.length; i++) {
			if(algo.equals(arr[i]))
			{
				isValidAlgo = true;
				break;
			}
		}
		
		JWS jws = new JWS();
		
		if(isValidAlgo)
		{
			if(algo.equalsIgnoreCase("HS256") || algo.equalsIgnoreCase("HS384") || algo.equalsIgnoreCase("HS512"))
			{
				if (sharedsecret == null || sharedsecret.trim().length() == 0) {
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Sharedkey is Empty", algo)).build();
				}
				
				try {
					jwspojo jwspojo = jws.sign(algo, payload, sharedsecret);
					Gson gson = new Gson();
					String json = gson.toJson(jwspojo, jwspojo.class);
					return Response.status(200).entity(json).build();
				} catch (Exception e) {
					return Response.status(Response.Status.NOT_FOUND)
							.entity(String.format("Error in Signing %s ", e)).build();
				}
			}
			
			if(algo.equalsIgnoreCase("RS256") || algo.equalsIgnoreCase("RS384") || algo.equalsIgnoreCase("RS512") || algo.equalsIgnoreCase("PS256") || algo.equalsIgnoreCase("PS384") || algo.equalsIgnoreCase("PS512") )
			{
				if (key == null || key.trim().length() == 0) {
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s RSA Private key required", key)).build();
				}
				
				if((key.contains("BEGIN PRIVATE KEY") && key.contains("END PRIVATE KEY")) || (key.contains("BEGIN RSA PRIVATE KEY") && key.contains("END RSA PRIVATE KEY")) )
				{
					try {
						jwspojo jwspojo = jws.sign(algo, payload, null, key);
						Gson gson = new Gson();
						String json = gson.toJson(jwspojo, jwspojo.class);
						return Response.status(200).entity(json).build();
					} catch (Exception e) {
						return Response.status(Response.Status.NOT_FOUND)
								.entity(String.format("Error in Signing %s ", e)).build();
					}
					
				}else{
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s RSA Private key Invalid", key)).build();
				}
			}
			
			if(algo.equalsIgnoreCase("ES256") || algo.equalsIgnoreCase("ES384") || algo.equalsIgnoreCase("ES512") )
			{
				
				if (key == null || key.trim().length() == 0) {
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s EC Private key required", key)).build();
				}
				
				if((key.contains("BEGIN EC PRIVATE KEY") && key.contains("END EC PRIVATE KEY")) )
				{
					try {
						jwspojo jwspojo = jws.sign(algo, payload, null, key);
						Gson gson = new Gson();
						String json = gson.toJson(jwspojo, jwspojo.class);
						return Response.status(200).entity(json).build();
					} catch (Exception e) {
						return Response.status(Response.Status.NOT_FOUND)
								.entity(String.format("Error in Signing %s ", e)).build();
					}
					
				}else{
					return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s EC Private key Invalid", key)).build();
				}
				
			}
			
			
			
		}else{
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Invalid JWS Algo", algo)).build();
		}
		return null;
		
		
		
		
	}
	

}
