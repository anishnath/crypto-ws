package ocsp;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import cacerts.Utils;
import pem.PemParser;
import pojo.ocsppojo;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

public class OCSP {

	/** root certificate */
	private X509Certificate rootCert;
	/** check certificate */
	private X509Certificate checkCert;
	/** OCSP URL */
	private String url;

	/** Certificate BigInteger URL */
	private BigInteger biginteger;

	private ocsppojo ocsppojo = new ocsppojo();
	
	
	
	

	public ocsppojo getOcsppojo() {
		return ocsppojo;
	}

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public OCSP() {

	}

	public OCSP(String checkCert, String rootCert) throws Exception {

		PemParser parser = new PemParser();

		X509Certificate checkCerts = null;
		X509Certificate rootCerts = null;

		X509CertImpl checkCertsImpl = null;
		X509CertImpl checkrootCertsImpl = null;

		Object obj = parser.parsePemFileObject(checkCert);

		if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
			X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
			byte[] x509 = certificateHolder.getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			checkCerts = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(x509));
			checkCertsImpl = X509CertImpl.toImpl(checkCerts);

		} else if (obj instanceof sun.security.x509.X509CertImpl) {
			checkCertsImpl = (sun.security.x509.X509CertImpl) obj;
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			checkCerts = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(checkCertsImpl.getEncoded()));
		}

		else {
			throw new Exception("Input server cert is not x.509 certificate");
		}

		obj = parser.parsePemFileObject(rootCert);

		if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
			X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
			byte[] x509 = certificateHolder.getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			rootCerts = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(x509));
			checkrootCertsImpl = X509CertImpl.toImpl(rootCerts);

		} else if (obj instanceof sun.security.x509.X509CertImpl) {
			checkrootCertsImpl = (sun.security.x509.X509CertImpl) obj;
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			rootCerts = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(checkrootCertsImpl.getEncoded()));
		}

		else {
			throw new Exception("Input root cert is not x.509 certificate");
		}

		URI uri = getResponderURI(checkCertsImpl);

		if (uri == null) {
			throw new Exception("No OCSCP URI detected ");
		}

		ocsppojo.setOcspurl("OCSP URL: " + uri);

		this.checkCert = checkCerts;
		this.rootCert = rootCerts;
		this.url = uri.toString();
		this.biginteger = checkCerts.getSerialNumber();

	}

	static URI getResponderURI(X509CertImpl certImpl) {

		// Examine the certificate's AuthorityInfoAccess extension
		AuthorityInfoAccessExtension aia = certImpl.getAuthorityInfoAccessExtension();
		if (aia == null) {
			return null;
		}

		List<AccessDescription> descriptions = aia.getAccessDescriptions();
		for (AccessDescription description : descriptions) {
			if (description.getAccessMethod().equals((Object) AccessDescription.Ad_OCSP_Id)) {

				GeneralName generalName = description.getAccessLocation();
				if (generalName.getType() == GeneralNameInterface.NAME_URI) {
					URIName uri = (URIName) generalName.getName();
					return uri.getURI();
				}
			}
		}
		return null;
	}

	public OCSP(X509Certificate checkCert, X509Certificate rootCert, String url) {
		this.checkCert = checkCert;
		this.rootCert = rootCert;
		this.url = url;
	}

	public static byte[] createDocumentId() throws Exception {
		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (Exception e) {
			throw new Exception(e);
		}
		long time = System.currentTimeMillis();
		long mem = Runtime.getRuntime().freeMemory();
		long seq = System.currentTimeMillis();
		String s = time + "+" + mem + "+" + (seq++);
		return md5.digest(s.getBytes());
	}

	private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {

		// Add provider BC

		JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
		DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
		DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
		// Generate the id for the certificate we are looking for
		CertificateID id = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuerCert), serialNumber);

		// basic request generation with nonce
		OCSPReqBuilder gen = new OCSPReqBuilder();

		gen.addRequest(id);

		// create details for nonce extension
		Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
				new DEROctetString(new DEROctetString(createDocumentId()).getEncoded()));
		gen.setRequestExtensions(new Extensions(new Extension[] { ext }));

		return gen.build();
	}

	public byte[] getEncoded() throws Exception {
		try {
			OCSPReq request = generateOCSPRequest(this.rootCert, checkCert.getSerialNumber());
			byte[] array = request.getEncoded();
			URL urlt = new URL(url);
			HttpURLConnection con = (HttpURLConnection) urlt.openConnection();
			con.setRequestProperty("Content-Type", "application/ocsp-request");
			con.setRequestProperty("Accept", "application/ocsp-response");
			con.setDoOutput(true);
			OutputStream out = con.getOutputStream();
			DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
			dataOut.write(array);
			dataOut.flush();
			dataOut.close();
			if (con.getResponseCode() / 100 != 2) {
				throw new IOException("Invalid HTTP response");
			}
			// Get Response
			InputStream in = (InputStream) con.getContent();
			OCSPResp ocspResponse = new OCSPResp(in);

			if (ocspResponse.getStatus() != 0)
				throw new IOException("Invalid status: " + ocspResponse.getStatus());
			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
			if (basicResponse != null) {
				SingleResp[] responses = basicResponse.getResponses();
				if (responses.length == 1) {
					SingleResp resp = responses[0];
					Object status = resp.getCertStatus();
					if (status == CertificateStatus.GOOD) {
						return basicResponse.getEncoded();
					} else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
						throw new IOException("OCSP Status is revoked!");
					} else {
						throw new IOException("OCSP Status is unknown!");
					}
				}
			}
		} catch (Exception ex) {
			throw new Exception(ex);
		}
		return null;
	}

	public void sendOCSPReq() throws Exception {
		OCSPReq request = generateOCSPRequest(this.rootCert, this.biginteger);

		StringBuilder ocsprequtes = new StringBuilder();

		ocsprequtes.append("OCSP Request Data:\n");
		ocsprequtes.append("\tVersion:" + request.getVersionNumber() + "\n");
		ocsprequtes.append("\tRequestor List:"+ "\n");
		ocsprequtes.append("\t\tCertificate ID:"+ "\n");

		if (request.getRequestorName() != null) {
			ocsprequtes.append("\t\t\tRequester Name: " + request.getRequestorName()+ "\n");
		}
		ocsprequtes.append("\t\t\tHash Algorithm: " + "SHA1"+ "\n");
		ocsprequtes.append("\t\t\tIssuer Key Hash: "
				+ Utils.toHexEncoded(request.getRequestList()[0].getCertID().getIssuerKeyHash())+ "\n");
		ocsprequtes.append("\t\t\tIssuer Name Hash: "
				+ Utils.toHexEncoded(request.getRequestList()[0].getCertID().getIssuerNameHash())+ "\n");
		ocsprequtes.append("\t\t\tSerial Number: " + request.getRequestList()[0].getCertID().getSerialNumber()+ "\n");

		ocsppojo.setOcsprequest(ocsprequtes.toString());

		byte[] bytes = request.getEncoded();

		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setRequestProperty("Content-Type", "application/ocsp-request");
		connection.setRequestProperty("Accept", "application/ocsp-response");
		connection.setDoOutput(true);

		DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(connection.getOutputStream()));
		outputStream.write(bytes);
		outputStream.flush();
		outputStream.close();
		if (connection.getResponseCode() != 200) {
			throw new Exception(
					"OCSP request has been failed " + connection.getResponseCode() + connection.getResponseMessage());
		}
		try {
			InputStream in = (InputStream) connection.getContent();

			OCSPResp ocspresp = new OCSPResp(in);

			StringBuilder response = new StringBuilder();

			response.append("OCSP Response Data:"+ "\n");

			//System.out.println(ocspresp.getStatus());

			response.append("\tOCSP Response Status:" + ocspresp.getStatus()+ "\n");
			// System.out.println("\tVersion:" +
			// ASN1Dump.dumpAsString(ocspresp.toASN1Structure().toASN1Object()));

			BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspresp.getResponseObject();

			if (basicOCSPResp != null) {

				response.append("\tOCSP Response Version:" + basicOCSPResp.getVersion()+ "\n");

				// System.out.println(basicOCSPResp.getSignatureAlgOID());

				// System.out.println("OCSP Class - " + o.getClass() +
				// ASN1Dump.dumpAsString(o, true));

				X509CertificateHolder[] holder = basicOCSPResp.getCerts();

				if (holder != null) {
					for (int i = 0; i < holder.length; i++) {

						response.append("holder"+ "\n");

						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

						in = new ByteArrayInputStream(holder[0].getEncoded());

						X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

						response.append(cert.toString());

					}
				}

				response.append("\tResponder Id:" + basicOCSPResp.getResponderId().toASN1Primitive().getName()+ "\n");
				response.append("\tProduced At:" + basicOCSPResp.getProducedAt()+ "\n");
				response.append("\tResponses:"+ "\n");
				response.append("\tCertificate ID:"+ "\n");

				for (int i = 0; i < basicOCSPResp.getResponses().length; i++) {

					SingleResp resp = basicOCSPResp.getResponses()[i];

					if (resp.getCertStatus() == null) {
						response.append("\t\tCert Status:" + "GOOD"+ "\n");
						ocsppojo.setCertstatus("GOOD"+ "\n");
					}

					Object status = resp.getCertStatus();

					if (resp.getCertStatus() != null) {
						if (status == CertificateStatus.GOOD) {
							response.append("\t\tCert Status:" + "GOOD"+ "\n");
							ocsppojo.setCertstatus("GOOD");
						} else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
							response.append("\t\tCert Status:" + "REVOKED"+ "\n");
							ocsppojo.setCertstatus("REVOKED");
						} else if (status instanceof org.bouncycastle.ocsp.UnknownStatus) {
							response.append("\t\tCert Status:" + "UNKNOWN"+ "\n");
							ocsppojo.setCertstatus("UNKNOWN");
						}
					}

					response.append("\t\tHash Algorithm OID:" + resp.getCertID().getHashAlgOID()+ "\n");
					response.append("\t\tSerial Number: " + resp.getCertID().getSerialNumber()+ "\n");
					response.append("\t\tIssuer Key Hash: " + Utils.toHexEncoded(resp.getCertID().getIssuerKeyHash())+ "\n");
					response.append(
							"\t\tIssuer Name Hash: " + Utils.toHexEncoded(resp.getCertID().getIssuerNameHash())+ "\n");
					response.append("\t\tThis Update: " + resp.getThisUpdate()+ "\n");
					response.append("\t\tNext Update: " + resp.getNextUpdate()+ "\n");

				}

				response.append("\tSignature Algorithm:" + "\n\t\t" + Utils.toHexEncoded(basicOCSPResp.getSignature())+ "\n");

			}
			ocsppojo.setOcspresponse(response.toString());
		} catch (Exception ex) {
			throw new Exception(ex);
		}

	}

	public static void main(String[] args) throws Exception {

		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("x509.txt"));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			everything = sb.toString();
		} finally {
			br.close();
		}

		String everythingChain = "";
		br = new BufferedReader(new FileReader("chain.pem"));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			everythingChain = sb.toString();
		} finally {
			br.close();
		}

		PemParser parser = new PemParser();
		try {
			OCSP ocsp = new OCSP(everything, everythingChain);

			ocsp.sendOCSPReq();

			System.out.println(ocsp.ocsppojo.toString());

			// System.out.println(basicOCSPResp.getCerts().toString());

			// System.out.println("Cert
			// Status:"+basicOCSPResp.isSignatureValid(basicOCSPResp));

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
