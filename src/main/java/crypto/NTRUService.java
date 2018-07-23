package crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import cacerts.Utils;
//import ntru.NTRUSEncryptionDecryption;
import pojo.ntrupojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class NTRUService {

//@Path("/ntru")
//public class NTRUService {
//
//	private static String[] arr = { "EES1087EP2", "EES1087EP2_FAST", "EES1171EP1", "EES1171EP1_FAST", "EES1499EP1",
//			"EES1499EP1_FAST", "APR2011_439", "APR2011_439_FAST", "APR2011_743", "APR2011_743_FAST" };
//
//	@GET
//	@Path("/params")
//	@Produces({ "application/json" })
//	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
//	public Response getParam() {
//		Gson gson = new Gson();
//		String json = gson.toJson(arr);
//		return Response.status(200).entity(json).build();
//
//	}
//
//	@POST
//	@Path("/encrypt")
//	@Produces({ "application/json" })
//	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
//	public Response encryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,
//			@FormParam("p_ntru") String algo) {
//
//		if (msg == null || msg.trim().length() == 0) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("p_msg %s does not have a Message", msg)).build();
//		}
//
//		if (publicKey == null || publicKey.trim().length() == 0) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("publicKey %s Empty NTRU Public Key ", publicKey)).build();
//		}
//
//		if (algo == null || algo.trim().length() == 0) {
//			algo = "APR2011_743_FAST";
//		}
//
//		algo = algo.trim().toUpperCase();
//
//		boolean isValid = false;
//		for (int i = 0; i < arr.length; i++) {
//			if (algo.equals(arr[i])) {
//				isValid = true;
//				break;
//			}
//		}
//
//		if (!isValid) {
//			Gson gson = new Gson();
//			String json = gson.toJson(arr);
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Invvalid ntru param %s valid param are  %s ", algo, json)).build();
//		}
//
//		NTRUSEncryptionDecryption encryptionDecryption = new NTRUSEncryptionDecryption();
//		try {
//			InputStream stream = new ByteArrayInputStream(Utils.decodeBASE64(publicKey));
//			ntrupojo nreu = encryptionDecryption.encrypt(algo, msg, stream);
//			Gson gson = new Gson();
//			String json = gson.toJson(nreu);
//			return Response.status(200).entity(json).build();
//		} catch (Exception e) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Error Performing NTRU Encryption %s ", e)).build();
//		}
//
//	}
//	
//	
//	@POST
//	@Path("/decrypt")
//	@Produces({ "application/json" })
//	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
//	public Response decryptMsg(@FormParam("p_msg") String msg, @FormParam("p_key") String publicKey,@FormParam("p_privkey") String privateKey,
//			@FormParam("p_ntru") String algo) {
//
//		if (msg == null || msg.trim().length() == 0) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("p_msg %s does not have a Valid Message to decode", msg)).build();
//		}
//
//		if (publicKey == null || publicKey.trim().length() == 0) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("publicKey %s Empty NTRU Public Key ", publicKey)).build();
//		}
//		
//		if (privateKey == null || privateKey.trim().length() == 0) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("publicKey %s Empty NTRU Private Key ", privateKey)).build();
//		}
//
//
//		if (algo == null || algo.trim().length() == 0) {
//			algo = "APR2011_743_FAST";
//		}
//
//		algo = algo.trim().toUpperCase();
//
//		boolean isValid = false;
//		for (int i = 0; i < arr.length; i++) {
//			if (algo.equals(arr[i])) {
//				isValid = true;
//				break;
//			}
//		}
//
//		if (!isValid) {
//			Gson gson = new Gson();
//			String json = gson.toJson(arr);
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Invvalid ntru param %s valid param are  %s ", algo, json)).build();
//		}
//
//		NTRUSEncryptionDecryption encryptionDecryption = new NTRUSEncryptionDecryption();
//		
//		try {
//			InputStream stream = new ByteArrayInputStream(Utils.decodeBASE64(publicKey));
//			InputStream privstream = new ByteArrayInputStream(Utils.decodeBASE64(privateKey));
//			ntrupojo nreu = encryptionDecryption.decrypt(algo, msg, stream,privstream);
//			Gson gson = new Gson();
//			String json = gson.toJson(nreu);
//			return Response.status(200).entity(json).build();
//		} catch (Exception e) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Error Performing NTRU Encryption %s ", e)).build();
//		}
//
//	}
//	
//	
//	@POST
//	@Path("/generatekeypair")
//	@Produces({ "application/json" })
//	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
//	public Response generateKey(@FormParam("p_ntru") String ntru, @FormParam("p_password") String password,
//			@FormParam("p_salt") String salt) {
//		
//		if (password != null && password.trim().length() >20 ) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("p_password %s Password size must be less than 20", password)).build();
//		}
//
//		if (salt != null && salt.trim().length() > 20) {
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("p_salt %s salt size must be less than 20 ", salt)).build();
//		}
//
//		if (ntru == null || ntru.trim().length() == 0) {
//			ntru = "APR2011_743_FAST";
//		}
//		
//		boolean isValid = false;
//		for (int i = 0; i < arr.length; i++) {
//			if (ntru.equals(arr[i])) {
//				isValid = true;
//				break;
//			}
//		}
//
//		if (!isValid) {
//			Gson gson = new Gson();
//			String json = gson.toJson(arr);
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Invvalid ntru param %s valid param are  %s ", ntru, json)).build();
//		}
//		
//		boolean isEcrypted=false;
//		if(password!=null && password.length()>0)
//		{
//			isEcrypted=true;
//		}
//		
//		NTRUSEncryptionDecryption encryptionDecryption = new NTRUSEncryptionDecryption();
//		
//		try {
//			ntrupojo ntrupojo = encryptionDecryption.generateNTRUKeys(ntru, isEcrypted, password, salt);
//			Gson gson = new Gson();
//			String json = gson.toJson(ntrupojo);
//			return Response.status(200).entity(json).build();
//		} catch (Exception e) {
//			e.printStackTrace();
//			return Response.status(Response.Status.NOT_FOUND)
//					.entity(String.format("Error Generating NTRU Keys %s ", e)).build();
//		}
//		
//	}
//
//		
//	
//	
}
