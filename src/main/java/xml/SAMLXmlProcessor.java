package xml;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

import cacerts.Utils;
import pem.PemParser;
import pojo.samlpojo;

/**
 * 
 * @author Anish Nath
 * Demo @ https://8gwifi.org
 *
 */
public class SAMLXmlProcessor {

	public samlpojo signNode(String privateKey, String certificate, String xmlNode, String signAlgorithmSha)
			throws Exception {

		return signNode(privateKey, certificate, xmlNode, signAlgorithmSha, null, null);

	}

	public samlpojo signNode(String privateKey, String certificate, String xmlNode, String signAlgorithmSha,
			String password, String relayState) throws Exception {

		boolean certfound = false;
		boolean keyfound = false;

		if (certificate != null && certificate.contains("BEGIN RSA PRIVATE KEY")) {
			if (null == signAlgorithmSha || signAlgorithmSha.trim().length() == 0) {
				signAlgorithmSha = Constants.RSA_SHA512;
			}

			signAlgorithmSha = signAlgorithmSha.toLowerCase();
			if (!signAlgorithmSha.contains("rsa-")) {
				throw new Exception(
						"RSA private can only use RSA XMLSignature Algorithms (rsa-sha1,rsa-sha256,rsa-sha384,rsa-sha512)");
			}

		}

		if (privateKey != null && privateKey.contains("BEGIN RSA PRIVATE KEY")) {
			if (null == signAlgorithmSha || signAlgorithmSha.trim().length() == 0) {
				signAlgorithmSha = Constants.RSA_SHA512;
			}

			signAlgorithmSha = signAlgorithmSha.toLowerCase();
			if (!signAlgorithmSha.contains("rsa-")) {
				throw new Exception(
						"RSA private can only use RSA XMLSignature Algorithms (rsa-sha1,rsa-sha256,rsa-sha384,rsa-sha512)");
			}

		}

		//

		if (certificate != null && certificate.contains("BEGIN DSA PRIVATE KEY")) {
			if (null == signAlgorithmSha || signAlgorithmSha.trim().length() == 0) {
				signAlgorithmSha = Constants.DSA_SHA1;
			}

			signAlgorithmSha = signAlgorithmSha.toLowerCase();
			if (!signAlgorithmSha.contains("dsa-")) {
				throw new Exception("DSA private can only use DSA XMLSignature Algorithms (dsa-sha1,dsa-sha256)");
			}

		}

		if (privateKey != null && privateKey.contains("BEGIN DSA PRIVATE KEY")) {
			if (null == signAlgorithmSha || signAlgorithmSha.trim().length() == 0) {
				signAlgorithmSha = Constants.DSA_SHA1;
			}

			signAlgorithmSha = signAlgorithmSha.toLowerCase();
			if (!signAlgorithmSha.contains("dsa-")) {
				throw new Exception("DSA private can only use DSA XMLSignature Algorithms (dsa-sha1,dsa-sha256)");
			}

		}

		if (certificate != null && !certificate.contains("BEGIN DSA PRIVATE KEY")
				&& !certificate.contains("BEGIN RSA PRIVATE KEY") && !certificate.contains("BEGIN CERTIFICATE")) {
			certificate = Util.formatCert(certificate, true);
		}

		PemParser parser = new PemParser();

		X509Certificate cert = null;

		PrivateKey key = null;

		if (null == password) {
			password = "";
		}

		Object obj = parser.parsePemFileObject(certificate, password);

		if (obj instanceof java.security.cert.X509Certificate) {
			cert = (X509Certificate) obj;
			certfound = true;
		}

		if (!certfound) {
			obj = parser.parsePemFileObject(privateKey, password);

			if (obj instanceof java.security.PrivateKey) {
				key = (PrivateKey) obj;
				keyfound = true;
			}

			if (obj instanceof java.security.cert.X509Certificate) {
				cert = (X509Certificate) obj;
				certfound = true;
			}
		}

		if (!certfound) {
			throw new Exception("Please provide x509 certificate for Signing XML Node");
		}

		obj = parser.parsePemFileObject(privateKey, password);

		if (obj instanceof java.security.PrivateKey) {
			key = (PrivateKey) obj;
			keyfound = true;
		}

		if (!keyfound) {
			obj = parser.parsePemFileObject(certificate, password);

			if (obj instanceof java.security.PrivateKey) {
				key = (PrivateKey) obj;
				keyfound = true;
			}

			if (obj instanceof java.security.cert.X509Certificate) {
				cert = (X509Certificate) obj;
				certfound = true;
			}
		}

		if (!keyfound) {
			throw new Exception("Please provide private key information for Signing XML Node");
		}

		Document authNRequestDoc = Util.loadXML(xmlNode);
		
		if(authNRequestDoc==null)
		{
			throw new Exception("Invalid XML");
		}
		
		Node node = authNRequestDoc.getFirstChild();
		String authNRequestSigned = Util.addSign(node, key, cert, signAlgorithmSha);

		samlpojo samlpojo = new samlpojo();
		samlpojo.setNode(authNRequestSigned);
		if (relayState != null) {
			String type = "SAMLRequest";
			if (xmlNode.contains("samlp:Response")) {
				type = "SAMLResponse";
			}


			String signature = buildSignature(xmlNode, relayState, signAlgorithmSha, key, type);
			samlpojo.setSignature(signature);
		}

		return samlpojo;
	}

	public String buildSignature(String samlMessage, String relayState, String signAlgorithm, PrivateKey key,
			String type) throws Exception {

		String signature = "";

		String msg = type + "=" + Util.urlEncoder(samlMessage);
		if (StringUtils.isNotEmpty(relayState)) {
			msg += "&RelayState=" + Util.urlEncoder(relayState);
		}

		if (StringUtils.isEmpty(signAlgorithm)) {
			signAlgorithm = Constants.RSA_SHA1;
		}

		msg += "&SigAlg=" + Util.urlEncoder(signAlgorithm);

		try {
			signature = Util.base64encoder(Util.sign(msg, key, signAlgorithm));
		} catch (Exception e) {
			String errorMsg = "buildSignature error." + e.getMessage();
			throw new Exception(errorMsg);
		}

		if (signature.isEmpty()) {
			String errorMsg = "There was a problem when calculating the Signature of the " + type;

			throw new IllegalArgumentException(errorMsg);
		}


		return signature;
	}

	public static void main(String[] args) throws Exception {

		String certString = new String(Files.readAllBytes(Paths.get("saml.cert")));
		String keyString = new String(Files.readAllBytes(Paths.get("saml.key")));
		String authNRequest = new String(Files.readAllBytes(Paths.get("authn_request.xml")));

		String certWithoutHeads = "MIICeDCCAeGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBZMQswCQYDVQQGEwJ1czET"
				+ "MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYD"
				+ "VQQDDBVqYXZhLXNhbWwuZXhhbXBsZS5jb20wHhcNMTUxMDE4MjAxMjM1WhcNMTgw"
				+ "NzE0MjAxMjM1WjBZMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEV"
				+ "MBMGA1UECgwMT25lTG9naW4gSW5jMR4wHAYDVQQDDBVqYXZhLXNhbWwuZXhhbXBs"
				+ "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALvwEktX1+4y2AhEqxVw"
				+ "OO6HO7Wtzi3hr5becRkfLYGjNSyhzZCjI1DsNL61JSWDO3nviZd9fSkFnRC4akFU"
				+ "m0CS6GJ7TZe4T5o+9aowQ6N8e8cts9XPXyP6Inz7q4sD8pO2EInlfwHYPQCqFmz/"
				+ "SDW7cDgIC8vb0ygOsiXdreANAgMBAAGjUDBOMB0GA1UdDgQWBBTifMwN3CQ5ZOPk"
				+ "V5tDJsutU8teFDAfBgNVHSMEGDAWgBTifMwN3CQ5ZOPkV5tDJsutU8teFDAMBgNV"
				+ "HRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAG3nAEUjJaA75SkzID5FKLolsxG5"
				+ "TE/0HU0+yEUAVkXiqvqN4mPWq/JjoK5+uP4LEZIb4pRrCqI3iHp+vazLLYSeyV3k"
				+ "aGN7q35Afw8nk8WM0f7vImbQ69j1S8GQ+6E0PEI26qBLykGkMn3GUVtBBWSdpP09" + "3NuNLJiOomnHqhqj";

		// Util.loadCert(certWithoutHeads);

		samlpojo samlpojo = new SAMLXmlProcessor().signNode(keyString, certString, authNRequest,
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "helloanish", null);
		System.out.println(samlpojo);

		String arr[] = { "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256",
				"http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512",
				"http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2009/xmldsig11#dsa-sha256",
				"http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
				"http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
				"http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
				"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
				"http://www.w3.org/2000/09/xmldsig#enveloped-signature" };
		for (int i = 0; i < arr.length; i++) {
			try {
				// new XMLSingature().signNode(keyString,certString,
				// authNRequest, arr[i],"hello");
				;
				// System.out.println("Passed" + arr[i]);
			} catch (Exception e) {
				// e.printStackTrace();
				// System.err.println("Failed-- " + arr[i]);
			}
		}

	}

}
