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
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Invalid Algo", algo)).build();
		}
	}

}
