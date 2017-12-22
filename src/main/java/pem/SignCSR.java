package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import cacerts.Utils;

public class SignCSR {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static String key ="-----BEGIN RSA PRIVATE KEY-----\n" +
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
	
	public String sign(final String inputCSR, String privateKey )
	        throws Exception { 
		
		if(null == privateKey || privateKey.trim().length()==0 )
		{
			privateKey = key.trim();
		}
		
		byte[] content = inputCSR.trim().getBytes();

		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);
		Reader br = new BufferedReader(isr);
		PEMParser parser = new PEMParser(br);
		Object obj = parser.readObject();		
		if(obj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest)
		{
			PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest)obj;
			is = new ByteArrayInputStream(privateKey.trim().getBytes());
			isr = new InputStreamReader(is);
			br = new BufferedReader(isr);
			parser = new PEMParser(br);
			obj = parser.readObject();
			if (obj instanceof org.bouncycastle.openssl.PEMKeyPair)
			{
				PEMKeyPair pemKeyPair = (PEMKeyPair)obj;
				PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
				JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
				PrivateKey pk =  jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
				KeyPair kp  = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
				X509Certificate certificate = sign(certificationRequest, pk, kp);
				return Utils.toPem(certificate);
			}
			
			throw new Exception("No Private Key Found in the System");
		}
		throw new Exception("Not a Valid CSR ");
		
	}
	
	private X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair)
	        throws Exception {   

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
	            .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
	            .find(sigAlgId);

	    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
	            .getEncoded());
	    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair
	            .getPublic().getEncoded());
 
	    PKCS10CertificationRequest pk10Holder = (PKCS10CertificationRequest)inputCSR;

	    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
	            new X500Name("CN=8gwifi"), Utils.getRandomBigInteger(), new Date(
	                    System.currentTimeMillis()), new Date(
	                    System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
	                            * 1000), pk10Holder.getSubject(), keyInfo);
	    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
	            .build(foo);
	    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
	    org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();
	    //in newer version of BC such as 1.51, this is 
	    //org.spongycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure(); 

	    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

	    // Read Certificate
	    InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
	    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
	    is1.close();
	    return theCert;
	    //return null;
	}
	
	public static void main(String[] args) throws Exception {
		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("csr.txt"));
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
		SignCSR parser = new SignCSR();
		try {
			String message =  parser.sign(everything, null);
			System.out.println(message);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
