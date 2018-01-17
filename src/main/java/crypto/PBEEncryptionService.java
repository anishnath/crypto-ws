package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cipher.EncryptDecrypt;
import pbe.PBEEncryptDecrypt;
import pojo.EncodedMessage;


@Path("/pbe")
public class PBEEncryptionService {
	
	private static String[] pbe_algos = { "PBEWITHHMACSHA1ANDAES_128", "PBEWITHHMACSHA1ANDAES_256", "PBEWITHHMACSHA224ANDAES_128",
			"PBEWITHHMACSHA224ANDAES_256", "PBEWITHHMACSHA256ANDAES_128", "PBEWITHHMACSHA256ANDAES_256",
			"PBEWITHHMACSHA384ANDAES_128", "PBEWITHHMACSHA384ANDAES_256", "PBEWITHHMACSHA512ANDAES_128",
			"PBEWITHHMACSHA512ANDAES_256", "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
			"PBEWITHMD5AND192BITAES-CBC-OPENSSL", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", "PBEWITHMD5ANDDES",
			"PBEWITHMD5ANDRC2", "PBEWITHMD5ANDTRIPLEDES", "PBEWITHSHA1ANDDES", "PBEWITHSHA1ANDDESEDE",
			"PBEWITHSHA1ANDRC2", "PBEWITHSHA1ANDRC2_128", "PBEWITHSHA1ANDRC2_40", "PBEWITHSHA1ANDRC4_128",
			"PBEWITHSHA1ANDRC4_40", "PBEWITHSHA256AND128BITAES-CBC-BC", "PBEWITHSHA256AND192BITAES-CBC-BC",
			"PBEWITHSHA256AND256BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC", "PBEWITHSHAAND128BITRC2-CBC",
			"PBEWITHSHAAND128BITRC4", "PBEWITHSHAAND192BITAES-CBC-BC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",
			"PBEWITHSHAAND256BITAES-CBC-BC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND40BITRC2-CBC",
			"PBEWITHSHAAND40BITRC4", "PBEWITHSHAANDIDEA-CBC", "PBEWITHSHAANDTWOFISH-CBC" };
	
	@POST
	@Path("/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_secretkey") String secretkey, @FormParam("p_cipher") String cipherparamater, @FormParam("p_rounds") String rounds) {
		
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s secretkey is EMpty or Null", secretkey)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		boolean flag=false;
		cipherparamater = cipherparamater.trim();
		
		for (int i = 0; i < pbe_algos.length; i++) {
			if(pbe_algos[i].equalsIgnoreCase(cipherparamater))
			{
				flag=true;
				break;
			}
		}
		
		if(!flag)
		{
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < pbe_algos.length; i++) {
				builder.append(pbe_algos[i]);
				builder.append(",");
			}
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is not valid Supported Algos %s", cipherparamater,builder.toString())).build();
		}
		
		if (rounds == null || rounds.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s rounds is not valid ", rounds)).build();
		}
		
		int round=0;
		try
		{
			round=  (int) Double.parseDouble(rounds);  
		}
		catch(NumberFormatException e)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s rounds is not integer ", rounds)).build();
		}
		
		if(round>50000  || round < 0 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Supported rounds 1-49999 ", rounds)).build();
			
		}
		
		
		EncryptDecrypt encryptDecrypt  =  new EncryptDecrypt();
		
		try {
			String message =PBEEncryptDecrypt.encrypt(msg, secretkey, cipherparamater, round, null);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Encryption %s ", e)).build();
		}
		
	}
	
	@POST
	@Path("/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptMsg(@FormParam("p_msg") String msg, @FormParam("p_secretkey") String secretkey, @FormParam("p_cipher") String cipherparamater, @FormParam("p_rounds") String rounds) {
		
		if (msg == null || msg.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND).entity(String.format("param1 %s Empty msg", msg)).build();
		}

		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s secretkey is EMpty or Null", secretkey)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		if (secretkey == null || secretkey.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s secretkey is EMpty or Null", secretkey)).build();
		}

		if (cipherparamater == null || cipherparamater.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is EMpty or Null", cipherparamater)).build();
		}
		
		boolean flag=false;
		cipherparamater = cipherparamater.trim();
		
		for (int i = 0; i < pbe_algos.length; i++) {
			if(pbe_algos[i].equalsIgnoreCase(cipherparamater))
			{
				flag=true;
				break;
			}
		}
		
		if(!flag)
		{
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < pbe_algos.length; i++) {
				builder.append(pbe_algos[i]);
				builder.append(",");
			}
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s cipherparamater is not valid Supported Algos %s", cipherparamater,builder.toString())).build();
		}
		
		
		if (rounds == null || rounds.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s rounds is not valid ", rounds)).build();
		}
		
		int round=0;
		try
		{
			round=  (int) Double.parseDouble(rounds);  
		}
		catch(NumberFormatException e)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s rounds is not integer ", rounds)).build();
		}
		
		if(round>50000  || round < 0 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Supported rounds 1-49999 ", rounds)).build();
			
		}
		
		try {
			String message = PBEEncryptDecrypt.decrypt(msg, secretkey, cipherparamater, round, null);
			EncodedMessage encodedMessage = new EncodedMessage();
			encodedMessage.setMessage(message);
			Gson gson = new Gson();
			String json = gson.toJson(encodedMessage,EncodedMessage.class);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error in Decryption  %s ", e)).build();
		}
		
	}

}
