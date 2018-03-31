package xml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;

import com.onelogin.saml2.util.Util;

import pem.PemParser;

public class SAMLHelper {

	public boolean validateSignature(String xml, String certificate, final String fingerprint, final String alg,
			final String xpath) throws Exception {

		if (null == xml || xml.trim().length() == 0) {
			throw new Exception("Invalid SAML ");
		}

		if (null == certificate || certificate.trim().length() == 0) {
			throw new Exception("X.509 Certificate required for Signature Validation ");
		}

		PemParser parser = new PemParser();

		Object obj = parser.parsePemFileObject(certificate);

		X509Certificate cert = null;

		if (obj instanceof java.security.cert.X509Certificate) {
			cert = (X509Certificate) obj;
		}

		if (null == cert) {
			throw new Exception("Please provide a Valid X.509 certificate ");
		}

		Document doc = Util.loadXML(xml);

		if (doc == null) {
			throw new Exception("Invalid XML");
		}
		

		boolean isValid = Util.validateSign(doc, cert, fingerprint, alg, xpath);

		return isValid;

	}
	
	public String deflatedBase64(String message ) throws Exception
	{
		String s = Util.base64decodedInflated(message).toString();
		return s;
	}
	
	public String encodedBase64(String message ) throws Exception
	{
		return Util.base64encoder(message);
	}

	public static void main(String[] args) throws IOException {

		String certString = new String(Files.readAllBytes(Paths.get("authn_request.xml.deflated.base64")));
		System.out.println(certString);

		String s = Util.base64decodedInflated(certString).toString();

		System.out.println(s);
	}
}
