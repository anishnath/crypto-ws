package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import ocsp.OCSP;
import pojo.ocsppojo;

@Path("/ocsp")
public class OCSPService {
	
	@POST
	@Path("/query")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response queryOCSP(@FormParam("p_pem1") String pem1, @FormParam("p_pem2") String pem2,@FormParam("p_pem3") String pem3) {
		
		
		if (pem1 == null || pem1.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Server Cert %s is Empty or Null", pem1)).build();
		}

		if (pem2 == null || pem2.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("CA is  %s Empty or null ", pem2)).build();
		}
		
		
		pem1=pem1.trim();
		pem2=pem2.trim();
		
		if(pem1.equals(pem2))
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Server Certs and CA certs are equal")).build();
		}
		
		boolean isValid=false;
		
		if(!pem1.contains("BEGIN CERTIFICATE") && !pem1.contains("END CERTIFICATE"))
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem1 %s Input CRT is not Valid PEM format", pem1)).build();
		}
		
		if(!pem2.contains("BEGIN CERTIFICATE") && !pem2.contains("END CERTIFICATE"))
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_pem2 %s Input CRT is not Valid PEM format", pem2)).build();
		}
		
		try {
			OCSP ocsp = new OCSP(pem1, pem2);
			
			ocsp.sendOCSPReq();
			Gson gson = new Gson();
			String json1 = gson.toJson(ocsp.getOcsppojo(),ocsppojo.class);
			return Response.status(200).entity(json1).build();
			
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
	
		
	}
}
