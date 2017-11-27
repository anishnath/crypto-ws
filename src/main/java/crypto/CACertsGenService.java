package crypto;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cacerts.CAAuthorityPOJO;
import cacerts.GenerateCACerts;

/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

@Path("/cacerts")
public class CACertsGenService {
  
    @GET
    @Path("/{p_dnsname}")
    @Produces({"application/json"})
    public Response getCACerts(@PathParam("p_dnsname") String name) {
  
        
    	if(name==null  || name.trim().length()==0)
    	{
    		return Response
                    .status(Response.Status.NOT_FOUND)
                    .entity(
                    String.format(
                    "param1 %s does not have a valid CN Name", 
                    name))
                    .build();
    	}
    	

    	GenerateCACerts generateCACerts = new GenerateCACerts();
    	
    	CAAuthorityPOJO caAuthorityPOJO = (CAAuthorityPOJO )generateCACerts.generateCAAuthority(name);
    	
    	if(caAuthorityPOJO==null)
    	{
    		return Response
                    .status(Response.Status.NOT_FOUND)
                    .entity(
                    String.format(
                    "param1 %s Error Generating Test CA Hieraracy raise a Feature request ", 
                    name))
                    .build();
    	}
    	
    	Gson gson = new Gson();
    	
    	String json = gson.toJson(caAuthorityPOJO);
    	
    	
        return Response.status(200).entity(json).build();
  
    }
  
}
