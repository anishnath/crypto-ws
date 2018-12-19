package crypto;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import cacerts.Utils;
import nacl.nacl;

@Path("/nacl")
public class NaclService {

	@POST
	@Path("/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encrypt(@FormParam("p_msg") String message, @FormParam("p_nonce") String nonce,
			@FormParam("p_key") String key) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==key || key.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key is  EMpty %s", key)).build();
		}
		
		if(key!=null && key.length() !=32 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key length should be 32 %s", key)).build();
		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<48)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 24 bit in Hex", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		
		System.out.println();
		
		String encryptedMesage;
		try {
			encryptedMesage = nacl.encrypt(message, iv, key.getBytes());
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		
		return Response.status(200).entity(encryptedMesage).build();
		
	}
	
	@POST
	@Path("/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decrypt(@FormParam("p_msg") String message, @FormParam("p_nonce") String nonce,
			@FormParam("p_key") String key) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==key || key.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key is  EMpty %s", key)).build();
		}
		
		if(key!=null && key.length() !=32 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key length should be 32 %s", key)).build();
		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<48)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 24 bit in Hex", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		String encryptedMesage;
		try {
			encryptedMesage = nacl.decrypt(message, iv, key.getBytes());
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		
		return Response.status(200).entity(encryptedMesage).build();
		
	}
	
	
	
	@POST
	@Path("/encrypt/aead")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response encryptaead(@FormParam("p_msg") String message, @FormParam("p_aead") String aead,@FormParam("p_nonce") String nonce,
			@FormParam("p_key") String key) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==aead || aead.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("aead is  EMpty %s", aead)).build();
		}
		
		if(null==key || key.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key is  EMpty %s", key)).build();
		}
		
		if(key!=null && key.length() !=32 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key length should be 32 %s", key)).build();
		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<8)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 8 bit in Hex", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		
		System.out.println();
		
		String encryptedMesage;
		try {
			encryptedMesage = nacl.aeadencrypt(message,aead, iv, key.getBytes());
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		
		return Response.status(200).entity(encryptedMesage).build();
		
	}
	
	@POST
	@Path("/box/decrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response boxdecrypt(@FormParam("p_msg") String message, @FormParam("p_key") String privatekey,@FormParam("p_pubkey") String publickey,@FormParam("p_nonce") String nonce) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==privatekey || privatekey.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Private Key is  EMpty %s", privatekey)).build();
		}
		
		if(null==publickey || publickey.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publickey Key is  EMpty %s", privatekey)).build();
		}
		
		if(publickey.length()!=64)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publickey Key is  Invalid must of of 32 bit hex(64) %s", privatekey)).build();
		}
		
		if(privatekey.length()!=64)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("privatekey Key is  Invalid must of of 32 bit hex(64) %s", privatekey)).build();
		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<48)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 24 bit in Hex(48)", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		String encryptedMesage;
		try {
			encryptedMesage = nacl.boxdecrypt(message, publickey, privatekey, iv);
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		
		return Response.status(200).entity(encryptedMesage).build();
		
	}
	
	
	@POST
	@Path("/box/encrypt")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response boxencrypt(@FormParam("p_msg") String message, @FormParam("p_key") String privatekey,@FormParam("p_pubkey") String publickey,@FormParam("p_nonce") String nonce) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==privatekey || privatekey.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Private Key is  EMpty %s", privatekey)).build();
		}
		
		if(null==publickey || publickey.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publickey Key is  EMpty %s", privatekey)).build();
		}
		
		if(publickey.length()!=64)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("publickey Key is  Invalid must of of 32 bit hex(64) %s", privatekey)).build();
		}
		
		if(privatekey.length()!=64)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("privatekey Key is  Invalid must of of 32 bit hex(64) %s", privatekey)).build();
		}
		
//		if(null==key || key.trim().length()==0)
//		{
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("key is  EMpty %s", key)).build();
//		}
		
//		if(key!=null && key.length() !=32 )
//		{
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("key length should be 32 %s", key)).build();
//		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<48)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 24 bit in Hex ", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		
		System.out.println();
		
		String encryptedMesage;
		try {
			encryptedMesage = nacl.boxencrypt(message, publickey, privatekey, iv);
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		return Response.status(200).entity(encryptedMesage).build();
		
	}
	
	@POST
	@Path("/decrypt/aead")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response decryptaead(@FormParam("p_msg") String message,  @FormParam("p_aead") String aead, @FormParam("p_nonce") String nonce,
			@FormParam("p_key") String key) 
	{
		
		if(null==message || message.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Message is  EMpty %s", message)).build();
		}
		
		if(null==aead || aead.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("aead is  EMpty %s", aead)).build();
		}
		
		if(null==key || key.trim().length()==0)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key is  EMpty %s", key)).build();
		}
		
		if(key!=null && key.length() !=32 )
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("key length should be 32 %s", key)).build();
		}
		
		
		byte [] iv;
		
		if(null==nonce || nonce.trim().length()==0)
		{
		
			iv = Utils.getIV(24);
		}
		
		if(nonce!=null && nonce.trim().length()<8)
		{
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Nonce is  Invalid %s it must be 8 bit in Hex", nonce)).build();
		}
		else {
			iv = Utils.hexToBytes(nonce);
			
		}
		nacl nacl = new nacl();
		String encryptedMesage;
		try {
			encryptedMesage = nacl.aeaddecrypt(message,aead, iv, key.getBytes());
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Message %s ", e)).build();
		}
		
		return Response.status(200).entity(encryptedMesage).build();
		
	}

}
