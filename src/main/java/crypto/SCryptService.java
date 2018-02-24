package crypto;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import generator.SCryptGen;
import pojo.EncodedMessage;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */
@Path("/scrypt")
public class SCryptService {

	private final SCryptGen scrypt = new SCryptGen();

	@POST
	@Path("/generatehash")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateHash(@FormParam("p_passphrase") final String passphrase,
			@FormParam("p_salt") final String salt, @FormParam("p_n") String cpucost,
			@FormParam("p_r") String memorycost, @FormParam("p_p") String paralleliZation,
			@FormParam("p_outputlength") String keyLength) {

		if (passphrase == null || passphrase.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_passphrase %s Provide a Password to Hash ", passphrase)).build();
		}
		
		if (salt == null || salt.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_salt %s Give the Salt Value", passphrase)).build();
		}

		if (cpucost == null || cpucost.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s CPU Cost is EMpty or Null ", cpucost)).build();
		}

		if (memorycost == null || memorycost.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Memory Cost is EMpty or Null ", memorycost)).build();
		}

		if (paralleliZation == null || paralleliZation.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s paralleliZation EMpty or Null ", paralleliZation)).build();
		}

		if (keyLength == null || keyLength.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s keyLength EMpty or Null ", paralleliZation)).build();
		}

		final int cpuCost;
		final int memoryCost;
		final int parallelization;
		final int keylength;

		try {
			cpuCost = Integer.parseInt(cpucost);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s CPU Cost Must be Integer ", cpucost)).build();

		}

		try {
			memoryCost = Integer.parseInt(memorycost);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Memmory Cost Cost Must be Integer ", memorycost)).build();

		}

		try {
			parallelization = Integer.parseInt(paralleliZation);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_p %s paralleliZation Must be Integer ", paralleliZation)).build();

		}

		try {
			keylength = Integer.parseInt(keyLength);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_outputlength %s keyLength Must be Integer ", keyLength)).build();

		}

		if (cpuCost <= 1) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Cpu cost parameter N must be > 1 ", cpucost)).build();
		}

		if (!isPowerOf2(cpuCost)) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Cost parameter N must be > 1 and a power of 2 ", cpucost)).build();
		}

		if (memoryCost == 1 && cpuCost > 65536) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Cpu cost parameter N must be > 1 and < 65536 ", memorycost)).build();
		}
		if (memoryCost < 1) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Memory cost must be >= 1 ", memorycost)).build();

		}
		int maxParallel = Integer.MAX_VALUE / (128 * memoryCost * 8);
		if (parallelization < 1 || parallelization > maxParallel) {
			return Response.status(Response.Status.NOT_FOUND).entity("Parallelisation parameter p must be >= 1 and <= "
					+ maxParallel + " (based on block size r of " + memoryCost + ")").build();

		}
		if (keylength < 1 || keylength > Integer.MAX_VALUE) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity("Key length must be >= 1 and <= " + Integer.MAX_VALUE).build();
		}

		final int saltLength = salt.length();

		if (saltLength < 1 || saltLength > Integer.MAX_VALUE) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity("Salt length must be >= 1 and <= " + Integer.MAX_VALUE).build();

		}

		try {

			Callable<Object> callable = new Callable<Object>() {
				public Object call() throws Exception {
					return scrypt.SCryptPasswordEncoder(passphrase, salt, cpuCost, memoryCost, parallelization,
							keylength, saltLength);
				}
			};

			ExecutorService executorService = Executors.newCachedThreadPool();
			Object result = null;
			Future<Object> task = executorService.submit(callable);
			try {
				// ok, wait for 15 seconds max
				result = task.get(15, TimeUnit.SECONDS);

				EncodedMessage encodedMessage = new EncodedMessage();
				encodedMessage.setBase64Encoded((String) result);
				Gson gson = new Gson();

				String json = gson.toJson(encodedMessage);
				return Response.status(200).entity(json).build();

			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Performing SCrypt Encryption %s ", e)).build();
			}

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing SCrypt Encryption %s ", e)).build();
		}
	}

	@POST
	@Path("/verifyhash")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response verifyHash(@FormParam("p_rawpassphrase") final String rawPassphrase,
			@FormParam("p_passphrase") final String passphrase, @FormParam("p_salt") final String salt,
			@FormParam("p_n") String cpucost, @FormParam("p_r") String memorycost,
			@FormParam("p_p") String paralleliZation, @FormParam("p_outputlength") String keyLength) {

		if (passphrase == null || passphrase.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_passphrase %s Provide a Password to Hash ", passphrase)).build();
		}
		
		if (salt == null || salt.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_salt %s Give the Salt Value", passphrase)).build();
		}

		if (cpucost == null || cpucost.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s CPU Cost is EMpty or Null ", cpucost)).build();
		}

		if (memorycost == null || memorycost.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Memory Cost is EMpty or Null ", memorycost)).build();
		}

		if (paralleliZation == null || paralleliZation.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s paralleliZation EMpty or Null ", paralleliZation)).build();
		}

		if (keyLength == null || keyLength.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s keyLength EMpty or Null ", paralleliZation)).build();
		}

		if (rawPassphrase == null || rawPassphrase.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s rawPassphrase EMpty or Null ", paralleliZation)).build();
		}

		final int cpuCost;
		final int memoryCost;
		final int parallelization;
		final int keylength;

		try {
			cpuCost = Integer.parseInt(cpucost);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s CPU Cost Must be Integer ", cpucost)).build();

		}

		try {
			memoryCost = Integer.parseInt(memorycost);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Memmory Cost Cost Must be Integer ", memorycost)).build();

		}

		try {
			parallelization = Integer.parseInt(paralleliZation);
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_p %s paralleliZation Must be Integer ", paralleliZation)).build();

		}

		try {
			keylength = Integer.parseInt(keyLength);
			
			if(keylength>3000)
			{
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("p_outputlength %s Max Supported keyLength 3000 ", keyLength)).build();
			}
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_outputlength %s keyLength Must be Integer ", keyLength)).build();

		}

		if (cpuCost <= 1) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Cpu cost parameter N must be > 1 ", cpucost)).build();
		}

		if (!isPowerOf2(cpuCost)) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Cost parameter N must be > 1 and a power of 2 ", cpucost)).build();
		}

		if (memoryCost == 1 && cpuCost > 65536) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Cpu cost parameter N must be > 1 and < 65536 ", memorycost)).build();
		}
		if (memoryCost < 1) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_r %s Memory cost must be >= 1 ", memorycost)).build();

		}
		int maxParallel = Integer.MAX_VALUE / (128 * memoryCost * 8);
		if (parallelization < 1 || parallelization > maxParallel) {
			return Response.status(Response.Status.NOT_FOUND).entity("Parallelisation parameter p must be >= 1 and <= "
					+ maxParallel + " (based on block size r of " + memoryCost + ")").build();

		}
		if (keylength < 1 || keylength > Integer.MAX_VALUE) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity("Key length must be >= 1 and <= " + Integer.MAX_VALUE).build();
		}

		final int saltLength = salt.length();

		if (saltLength < 1 || saltLength > Integer.MAX_VALUE) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity("Salt length must be >= 1 and <= " + Integer.MAX_VALUE).build();

		}

		try {

			Callable<Object> callable = new Callable<Object>() {
				public Object call() throws Exception {
					return scrypt.SCryptPasswordEncoder(passphrase, salt, cpuCost, memoryCost, parallelization,
							keylength, saltLength);
				}
			};

			ExecutorService executorService = Executors.newCachedThreadPool();
			Object result = null;
			Future<Object> task = executorService.submit(callable);
			try {
				// ok, wait for 15 seconds max
				result = task.get(15, TimeUnit.SECONDS);
				String message = "hash Verification Failed";
				if (rawPassphrase.equals(result)) {
					message = "hash Verification Sucessfull";
				}

				Gson gson = new Gson();
				
				EncodedMessage encodedMessage = new EncodedMessage();
				encodedMessage.setBase64Encoded((String) result);
				encodedMessage.setMessage(message);
				
				String json = gson.toJson(encodedMessage);
				return Response.status(200).entity(json).build();

			} catch (Exception e) {
				return Response.status(Response.Status.NOT_FOUND)
						.entity(String.format("Error Performing SCrypt password Hash Verification %s ", e)).build();
			}

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("Error Performing SCrypt password Hash Verification %s ", e)).build();
		}
	}

	private static boolean isPowerOf2(int x) {
		return ((x & (x - 1)) == 0);
	}

}
