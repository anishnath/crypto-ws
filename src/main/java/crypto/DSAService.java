package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;
import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;

import dsa.DSASigner;
import pgp.pgppojo;

/**
 * 
 * @author Anish Nath
 * Demo @ https://8gwifi.org
 *
 */

@Path("/dsa")
public class DSAService {


	private static String[] arr = { "SHA256withDSA", "NONEwithDSA", "SHA224withDSA", "SHA1withDSA" };

	@GET
	@Path("/{p_keysize}")
	@Produces({ "application/json" })
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response generateKey(@PathParam("p_keysize") String keysize) {

		

		if (keysize == null || keysize.trim().length() == 0) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_keysize %s Keysize is EMpty valid value {1024,2048,4096}", keysize))
					.build();
		}

		int keySize = 1024;
		try {
			keySize = Integer.parseInt(keysize.trim());
		} catch (NumberFormatException e) {

			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("p_n %s Input key size is String  ", keysize)).build();

		}

		if (keySize > 3072) {
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format(
							"p_n %s Input key size values must be between 1024 and 3072 and a multiple of 1024  ",
							keysize))
					.build();
		}

		DSASigner dsaPublicPrivateKeys = new DSASigner();

		try {
			pgppojo pgppojo = dsaPublicPrivateKeys.generateKey(keySize);
			Gson gson = new Gson();

			String json = gson.toJson(pgppojo);
			return Response.status(200).entity(json).build();
		} catch (Exception e) {
			e.printStackTrace();
			return Response.status(Response.Status.NOT_FOUND)
					.entity(String.format("param1 %s Error Generating Keys  ", e)).build();
		}

	}

	@POST
	@Path("/sign")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	public Response sign(@FormDataParam("p_file") InputStream uploadedInputStream,
			@FormDataParam("p_file") FormDataContentDisposition fileDetail, @FormDataParam("p_key") String publicKey,
			@FormDataParam("p_algo") String algo) {

		
		// check if all form parameters are provided
		if (uploadedInputStream == null || fileDetail == null)
			return Response.status(404).entity("Input file is EMpty or Null ").build();

		if (null == publicKey || publicKey.trim().length() == 0)
			return Response.status(404).entity("DSA private key is EMpty or Null ").build();

		if (null == algo || algo.trim().length() == 0)
			return Response.status(404)
					.entity("DSA Algorithm is EMpty or Null valid Algo SHA256withDSA,NONEwithDSA,SHA224withDSA,SHA1withDSA ")
					.build();

		algo = algo.trim();
		boolean isValidAlgo = false;
		for (int i = 0; i < arr.length; i++) {
			if (algo.toUpperCase().equals(arr[i].toUpperCase())) {
				isValidAlgo = true;
			}
		}

		if (!isValidAlgo) {
			return Response.status(404)
					.entity("DSA Algorithm valid Algos are SHA256withDSA,NONEwithDSA,SHA224withDSA,SHA1withDSA ")
					.build();
		}

		String path = System.getProperty("java.io.tmpdir");
		String fullPath = path + "/" + UUID.randomUUID().toString();

		File file = new File(fullPath);
		File file1 = null;

		try {
			// 10 MB Max
			InputStream in = new LimitedSizeInputStream(uploadedInputStream, 10485760);

			OutputStream out = new FileOutputStream(fullPath);
			IOUtils.copy(in, out);

			// file.deleteOnExit();

		} catch (Exception e) {
			return Response.status(404).entity("Max File Size Supported is 10 MB").build();
		}

		try {
			if (publicKey.contains("BEGIN DSA PRIVATE KEY") && publicKey.contains("END DSA PRIVATE KEY")) {
				DSASigner dsaSigner = new DSASigner();

				byte[] bytesArray = new byte[(int) file.length()];

				FileInputStream fis = new FileInputStream(file);
				fis.read(bytesArray); // read file into bytes[]
				fis.close();

				byte[] message = dsaSigner.sign(bytesArray, publicKey, algo);

				fullPath = path + "/" + UUID.randomUUID().toString();

				FileOutputStream stream = new FileOutputStream(fullPath);
				try {
					stream.write(message);
				} finally {
					stream.close();
				}
				file1 = new File(fullPath);

				return Response.ok(file1, MediaType.APPLICATION_OCTET_STREAM)
						.header("Content-Disposition", "attachment; filename=\"" + fileDetail.getFileName() + ".sig\"") // optional
						.build();
			} else {
				return Response.status(404).entity("For File Signing Provide a valid DSA Private Key").build();
			}
		} catch (Exception e) {
			return Response.status(404).entity("Error performing DSA Signature " + e).build();
		} finally {
			try {
				if (file != null) {
					Files.deleteIfExists(Paths.get(file.getAbsolutePath()));
				}
				if (file1 != null) {
					Files.deleteIfExists(Paths.get(file.getAbsolutePath()));
				}
			} catch (IOException e) {
				// IGNORE..
			}
		}
	}

	@POST
	@Path("/verify")
	@Produces({ "application/json" })
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	public Response verify(@FormDataParam("p_file") InputStream uploadedInputStream,
			@FormDataParam("p_file") FormDataContentDisposition fileDetail,
			@FormDataParam("p_sig") InputStream signatureInputStream,
			@FormDataParam("p_sig") FormDataContentDisposition signatureDetail,
			@FormDataParam("p_key") String publicKey, @FormDataParam("p_algo") String algo) {
		
		
		System.out.println("Verify..");

		// check if all form parameters are provided
		if (signatureInputStream == null || signatureDetail == null)
			return Response.status(404).entity("Signature file is EMpty or Null ").build();

		// check if all form parameters are provided
		if (uploadedInputStream == null || fileDetail == null)
			return Response.status(404).entity("Input file is EMpty or Null ").build();

		if (null == publicKey || publicKey.trim().length() == 0)
			return Response.status(404).entity("DSA private key is EMpty or Null ").build();

		if (null == algo || algo.trim().length() == 0)
			return Response.status(404)
					.entity("DSA Algorithm is EMpty or Null valid Algo SHA256withDSA,NONEwithDSA,SHA224withDSA,SHA1withDSA ")
					.build();

		algo = algo.trim();
		boolean isValidAlgo = false;
		for (int i = 0; i < arr.length; i++) {
			if (algo.toUpperCase().equals(arr[i].toUpperCase())) {
				isValidAlgo = true;
			}
		}

		if (!isValidAlgo) {
			return Response.status(404)
					.entity("DSA Algorithm valid Algos are SHA256withDSA,NONEwithDSA,SHA224withDSA,SHA1withDSA ")
					.build();
		}

		String path = System.getProperty("java.io.tmpdir");
		String filefullPath = path + "/" + UUID.randomUUID().toString();
		String signaturefullPath = path + "/" + UUID.randomUUID().toString();

		File file = new File(filefullPath);
		File sigfile = new File(signaturefullPath);

		try {
			// 10 MB Max
			InputStream in = new LimitedSizeInputStream(uploadedInputStream, 10485760);
			OutputStream out = new FileOutputStream(filefullPath);
			IOUtils.copy(in, out);

		} catch (Exception e) {
			return Response.status(404).entity("Max File Size Supported is 10 MB").build();
		}

		try {
			// 5 MB Max
			InputStream in = new LimitedSizeInputStream(signatureInputStream, 5242880);
			OutputStream out = new FileOutputStream(signaturefullPath);
			IOUtils.copy(in, out);

		} catch (Exception e) {
			return Response.status(404).entity("Max Signature File Size Supported is 10 MB").build();
		}

		try {
			if (publicKey.contains("BEGIN PUBLIC KEY") && publicKey.contains("END PUBLIC KEY")) {
				DSASigner dsaSigner = new DSASigner();

				byte[] filebytesArray = new byte[(int) file.length()];

				FileInputStream fis = new FileInputStream(file);
				fis.read(filebytesArray); // read file into bytes[]
				fis.close();

				byte[] sigbytesArray = new byte[(int) sigfile.length()];

				fis = new FileInputStream(sigfile);
				fis.read(sigbytesArray); // read Signature file into bytes[]
				fis.close();

				boolean message = dsaSigner.verifysign(filebytesArray, sigbytesArray, publicKey, algo);

				if (message) {
					return Response.status(200).entity("Verification Succeeded").build();
				} else {
					return Response.status(200).entity("Verification failed").build();
				}

			} else {
				return Response.status(404).entity("For File Signing Provide a valid DSA Public Key").build();
			}
		} catch (Exception e) {
			return Response.status(404).entity("Error performing DSA Verification " + e).build();
		} finally {
			try {
				if (file != null) {
					//System.out.println(file.getAbsolutePath());
					Files.deleteIfExists(Paths.get(file.getAbsolutePath()));
				}
				if (sigfile != null) {
					//System.out.println(sigfile.getAbsolutePath());
					Files.deleteIfExists(Paths.get(sigfile.getAbsolutePath()));
				}
			} catch (Exception e) {
				// IGNORE..
			}
		}
	}

	public class LimitedSizeInputStream extends InputStream {

		private final InputStream original;
		private final long maxSize;
		private long total;

		public LimitedSizeInputStream(InputStream original, long maxSize) {
			this.original = original;
			this.maxSize = maxSize;
		}

		@Override
		public int read() throws IOException {
			int i = original.read();
			if (i >= 0)
				incrementCounter(1);
			return i;
		}

		@Override
		public int read(byte b[]) throws IOException {
			return read(b, 0, b.length);
		}

		@Override
		public int read(byte b[], int off, int len) throws IOException {
			int i = original.read(b, off, len);
			if (i >= 0)
				incrementCounter(i);
			return i;
		}

		private void incrementCounter(int size) throws IOException {
			total += size;
			if (total > maxSize) {

				throw new IOException("InputStream exceeded maximum size in bytes.");
			}
		}

	}

}
