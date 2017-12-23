package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.google.gson.Gson;

import cacerts.Utils;
import pojo.certpojo;

/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */
public class SelfSignGenerate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public certpojo generateCertificate(CertInfo certInfo, String privatekey, int version) throws Exception
	{
		if(null == privatekey || privatekey.trim().length()==0 )
		{
			throw new Exception("Private Key is Null or EMPTY");
		}
		
		byte[] content = privatekey.trim().getBytes();

		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);
		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);
		Object obj = parser.readObject();		
		
		if (obj instanceof org.bouncycastle.openssl.PEMKeyPair)
		{
			PEMKeyPair pemKeyPair = (PEMKeyPair)obj;
			PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
			PrivateKey pk =  jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			KeyPair kp  = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
			X509Certificate x509certs = generateCertificate(kp,certInfo,version);
			certpojo certpojo =  new certpojo();
			certpojo.setMessage(Utils.toPem(x509certs));
			certpojo.setMessage2(x509certs.toString());
			return certpojo;
			
		}
		throw new Exception("Failed to Created Self Signed Certificate with " + obj );
	}
	
	public certpojo generateCertificate(CertInfo certInfo, int version) throws Exception
	{
		KeyPair kp = Utils.generateRSAKeyPair("RSA", 2048);
		X509Certificate x509certs = generateCertificate(kp,certInfo,version);
		certpojo certpojo =  new certpojo();
		certpojo.setMessage(Utils.toPem(x509certs));
		certpojo.setMessage2(x509certs.toString());
		certpojo.setPrivatekey(Utils.toPem(kp));
		
		return certpojo;
		
	}

	private X509Certificate generateCertificate(KeyPair kp, CertInfo certInfo, int certVersion)
			throws SecurityException, Exception {

		// Issuer
		X500NameBuilder issuerBuilder = new X500NameBuilder();

		issuerBuilder.addRDN(BCStyle.C, certInfo.getCity());
		issuerBuilder.addRDN(BCStyle.O, certInfo.getCompany());
		issuerBuilder.addRDN(BCStyle.OU, certInfo.getDepartment());
		issuerBuilder.addRDN(BCStyle.CN, certInfo.getHostName());
		issuerBuilder.addRDN(BCStyle.EmailAddress, certInfo.getEmail());
		issuerBuilder.addRDN(BCStyle.CN, certInfo.getHostName());

		//
		// subjects name table.
		//
		X500NameBuilder subjectBuilder = new X500NameBuilder();

		subjectBuilder.addRDN(BCStyle.C, certInfo.getCity());
		subjectBuilder.addRDN(BCStyle.O, certInfo.getCompany());
		subjectBuilder.addRDN(BCStyle.OU, certInfo.getDepartment());
		subjectBuilder.addRDN(BCStyle.CN, certInfo.getHostName());
		subjectBuilder.addRDN(BCStyle.EmailAddress, certInfo.getEmail());

		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
		Calendar c = Calendar.getInstance();
		c.setTime(new Date()); // Now use today date.
		c.add(Calendar.DATE, certInfo.getExpiry()); // Adding Expiry

		BigInteger b = new BigInteger(256, new Random());
		X509Certificate cert = null;

		if (certVersion == 3) {

			X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(issuerBuilder.build(), b, new Date(),
					c.getTime(), subjectBuilder.build(), kp.getPublic());


			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

			v3Bldr.addExtension(Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(kp.getPublic()));

			v3Bldr.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(kp.getPublic()));
			
			String[] altnane = certInfo.getAlt_name();
			if(altnane!=null)
			{
			for (int i = 0; i < altnane.length; i++) {
				GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, altnane[i] ));
				v3Bldr.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
			}
			}

			

			X509CertificateHolder certHldr = v3Bldr
					.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(kp.getPrivate()));
			cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);
		}

		if (certVersion == 1) {
			X509v1CertificateBuilder x509v1CertificateBuilder = new JcaX509v1CertificateBuilder(issuerBuilder.build(),
					b, new Date(), c.getTime(), subjectBuilder.build(), kp.getPublic());
			X509CertificateHolder certHldr = x509v1CertificateBuilder
					.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(kp.getPrivate()));
			cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);
		}

		// cert.checkValidity(new Date());

		// cert.verify(kp.getPublic());

		return cert;

	}

	public static void main(String[] args) throws Exception {
		
		 String privakey1 ="-----BEGIN RSA PRIVATE KEY-----\n" +
	            "MIIEpAIBAAKCAQEA0i5/EgFtW57XT6m2Ysr2DLj37Dw0/7l1c081DJHQDna/ru4D\n" +
	            "8mHEuycUV44Q52EEWNHI5RHYNYDTeHvMpehSF+x4B6M8bw0yrEtzyg8vR9ObMGrR\n" +
	            "n2k/VX3MSM4Repecgmxms39Q0lxlvyd6OcNTh8XnJXwRFt28gm3rbJnQU1RVkNBt\n" +
	            "MoiiPJVKb/MAqrUAEVrTlekVc+wL9nxDROzzYinwxW5zSMyAYz/7fhutE3nwICjd\n" +
	            "AKLMvYz4gKb4nRZBrzuTP3C2HO0llTB38mepG/yu+rVFjuPXeGjuTVAYPM9QW45L\n" +
	            "1OOvsrm8Of2DQvcti518EuO0bmqwEsMe/LJ9qwIDAQABAoIBAQC+brhdJQPjdmiY\n" +
	            "2ijRHBmQ72paFTbj2DItVr+28soywK7uHONgkerAsyjAJ4zzRzi8DN9bhS6DU4TG\n" +
	            "7kw+qd7vpCYgrWrNJ4UZDIgNtHJfPr+mP7JMH/ztRbx43pSBoaqBlRv8WEdvQZ5C\n" +
	            "cs9QVMRzCQFkOiP1ttPczSD4VeimBefSHR4OFN1hJmBNLKOTUMINMUAsXr3KkWq8\n" +
	            "vyE0TkPTudOtvio1Wp9ZyhPEjztACyD414Q0/ziO5kl7o7PWBtWWju7EdeSq+9cs\n" +
	            "eJN/aC1l30TKFgnUHXcbMYS556yJtjMS1ZrUhcoK+OX33/4H8TkfVHWSaXVllUTO\n" +
	            "WELm+RVZAoGBAOx4ft4VA59PNa+d/k+PJmPKqUG3VK98Hwbz+O/7DXxu4VOzitCV\n" +
	            "nq1bI54f6iPWl8B035pbgx2faOoDp8hvmw9y4MA7mp+mXXmRI6flpT3qVRdFC3aG\n" +
	            "SfwPu+ZPQJ6tZf7fYFy41R+hrSLJ9BVsewbFnqbhz84Xu7MBbkY8NC03AoGBAOOK\n" +
	            "MWMyAvAYcKHlm2A9slzFZZPUEszfbrwUUJuJBuZBQToArMZM4I3snI74i9dV6/+m\n" +
	            "a8JROoLEWa3CsTvWKFJuRvpe/KxYeZAe1TXL29SOrSxCAmopZme62KuhPsxGYRoW\n" +
	            "1L9yn/ixqGwqcJtyff36RYi1wwZugT59Jdkn+00tAoGBAJlYTlUv5Why0kqvNxJa\n" +
	            "rzd5Xac6/tTJtckpfx4IfKdbtA02WeeHjx22A3PwGELjTwdEAxizDWSxUjSm6DAH\n" +
	            "h9NN2MdwH4Y2OVmzMB8Zwb1T75gmcxeKYAHwJhZlAG+l3IWaT3/xcGuRyZfMxNb7\n" +
	            "wRAUKRzpRHvOUi7z15H+SoujAoGAN/Xmy5SjMFVybf7ARd0mnrZVkxPXQ9e3rj34\n" +
	            "zSfYMIzf89nypBqIJ5+HqYnrKpyRHCDb48CCeWK9A4UcfbDf3dYNUspFrkVcMFvE\n" +
	            "6CQo/o/Qe1AIs/9WljBX1W4kuaydeQMgc61HNqzK1T9iznhMEEibDVJWkqBe3PV+\n" +
	            "d3fj0EkCgYAdf1NZqRtoB0srnLiTqQDapYYWckvD+62kWXmNfqF0XyfgVyYDAD/w\n" +
	            "bjBpX6dS1652yFlsZ9HQU1kJs1qMejz0O2XpCY96JFpcv7fJP6hso7AamxfBGusQ\n" +
	            "l5ZqplxkM4pWgzveJvzf70zrJ+rmjVbrErqzCZNYGnfmMcgNqzaFTg==\n" +
	            "-----END RSA PRIVATE KEY-----";

		KeyPair kp = Utils.generateRSAKeyPair("RSA", 2048);

		int exp = 200;

		CertInfo certInfo = new CertInfo("ansh", "OW", "AS", "Aasda@csd.com", "asd", "dsa", "das", exp);
		
		String json = certInfo.toString();
		
		//System.out.println(json);

		SelfSignGenerate generate = new SelfSignGenerate();
		X509Certificate cert = generate.generateCertificate(kp, certInfo,1);

		//System.out.println(cert);

		cert = generate.generateCertificate(kp, certInfo, 3);

		// System.out.println(cert);

		//System.out.println(Utils.toPem(cert));
		
		Gson gson = new Gson();
        HttpClient client = HttpClientBuilder.create().build();
        String url1 = "http://localhost:8082/crypto/rest/certs/genselfsignwithprivkey";
        HttpPost post = new HttpPost(url1);
        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
        urlParameters.add(new BasicNameValuePair("p_certinfo", json));
        urlParameters.add(new BasicNameValuePair("p_privatekey", privakey1));
        urlParameters.add(new BasicNameValuePair("p_version", "3"));
        post.addHeader("accept", "application/json");
        
        post.setEntity(new UrlEncodedFormEntity(urlParameters));
        post.addHeader("accept", "application/json");
        HttpResponse response1 = client.execute(post);
        
        System.out.println(response1.getStatusLine().getStatusCode() );
        

        BufferedReader br = new BufferedReader(
                new InputStreamReader(
                        (response1.getEntity().getContent())
                )
        );
        StringBuilder content = new StringBuilder();
        String line;
        while (null != (line = br.readLine())) {
            content.append(line);
        }
        
        certpojo certpojo1 = gson.fromJson(content.toString(), certpojo.class);
        
        System.out.println(certpojo1);

	}

}
