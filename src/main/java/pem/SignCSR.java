package pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.swing.text.StyledEditorKit.ForegroundAction;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import cacerts.Utils;

public class SignCSR {
	
	private static final String CA_CRL_ENDPOINT_URL = "https://8gwifi.org";
	private static final ASN1Encodable CA_OCSP_ENDPOINT_URL = null;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static String key ="-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAsXDeL6JLkgpsOABpfmc8hmUG39UX8PGXjTJlnVunr0NdSLNJ\n" +
            "Zk2jvzqH4IjHISX5N1LsWX6TS1FRabt92/x7Z88Gbz3b/bR4Ps3MKfehan0QXxl2\n" +
            "mMsxq5i2oNvqrETOah8zob2s1J1TycSh8ua0+IeX0I+rkzbDqu4joIFpByEvcjbp\n" +
            "L61YdCg1GYaXNbstqsYJmZHq5gII16bs3d48fBBt07rkDDyKVju01a9K0N32KzEE\n" +
            "IRKn02WpsV/IAgetJFvbS9fNRfrKCOebpqSTGbJFHmJYKX4vvzFDafC/c05BJ2is\n" +
            "THpGs4enEZ6UMjkGKSFmJnTwCfN3VKMFHeocbQIDAQABAoIBACdbKWzXSnux5B7n\n" +
            "uH5Y14vXjJbI5O6EJ2Eh9HfahG7TOjWNzpHqVo9rpAehTsmDaqtisRmIgZMLDkut\n" +
            "UlUgwx5bRMoXplu3U5RagRYt3peH9cGiHDP3naS50ogLPxnGiSHwmbseHt9ppdPy\n" +
            "0RjXIvyc1odj1mJomy2mdDB9g5YY36lWo1SpEOOA81GJqQu15cWUwmA+VdeAudH/\n" +
            "VlkevEVncatB4I5YK8+kf8GOuEHSnb24axpcQjtGDkmSasa8i7HQIn444XKGve6J\n" +
            "cLoma7Hr4vW6nwSB6sn7/QL8c6QAYeXtg6KbLt2+tcbJKZeDDlc5b13ahxbogfb6\n" +
            "39BwvuECgYEA1dp2FEEotigJxDA5MCnTuCdA4eNfPU74ubFPVVLeKNXpZq8SSfaB\n" +
            "wCLc7YQTEujh6NMGwn4tzwA3suXo7Z3pnC16qRL8UGZrbgTbYtPh8h2sJ5h6PhzK\n" +
            "fcGUAnk5lhD+yLgGV47xOTcdUB93or66SsIwki8vx0uCmiL7hCAhqhcCgYEA1GlJ\n" +
            "+lnM0EnVDqqEliaNHxYAt8F07kwbdfzmTx3cVhOzX0szUBzm/elBe9XLGnNGl2mG\n" +
            "8tQ3nD/xWmlkLcdRKsbEqQXLkqbHAOgpilYWExnCZsIcJeZc6x+7SADAWALbIYjl\n" +
            "VSkyhPIaQE50bUhw9mVBBSZLaYdb/yhpQEODtBsCgYEAyX1QC71o0lfe+85D07FV\n" +
            "Hgk+BJbqQSWLC8qX6NhvISKLCoihPrbXgWRXrCHopsRtNaS+lbm1B3g5AoHEeT1z\n" +
            "wgbHr02IFWiqh7pjyjXAiRKUBaqQYr1VvC8LeVkmfNH+fLeGojC37ySSpc9ANUJm\n" +
            "29EjWljDN49ZukiDmfV8QnkCgYEAv0oCwV7VwE59fTO7K62UMYaTJukl8OTBZkRW\n" +
            "9LEjmLEtPIhwsZkVvVyvCGLFAhEGZZ03VsAfRKuhI5b+DOwPAML4oG8DohJn7T0n\n" +
            "C9nzD0iHdhshVlBbJbPx6SokDh6kUVMDlOoBARE26uq8lx5B/OO65nRSPbsU8njm\n" +
            "MGWc2jkCgYBdeVpUFVwcxIUUODbvrHAoq/O9FO3O704DiuDaHRZ8uGXBm4lOOpS1\n" +
            "VaJ+xUIVJ5pwWhSG7Kd4vDrGDvz8tQzByAAAblyXQvQJgL1OyTwzLKXbjrlQkoGA\n" +
            "hBig2512AyfZZc18nhdKc+HKBbTH1Lef6Ym8GbCsW3BUmaV99d72cg==\n" +
            "-----END RSA PRIVATE KEY-----";
	
	private static String intCA="-----BEGIN CERTIFICATE-----\n" +
             "MIICxDCCAaygAwIBAgIEnNMcnTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZy\n" +
             "b290Q0EwHhcNMTgxMjA0MDk1MTEyWhcNMjUxMjMwMTgzMDAwWjAVMRMwEQYDVQQD\n" +
             "DApJbnRlcm1lZENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsXDe\n" +
             "L6JLkgpsOABpfmc8hmUG39UX8PGXjTJlnVunr0NdSLNJZk2jvzqH4IjHISX5N1Ls\n" +
             "WX6TS1FRabt92/x7Z88Gbz3b/bR4Ps3MKfehan0QXxl2mMsxq5i2oNvqrETOah8z\n" +
             "ob2s1J1TycSh8ua0+IeX0I+rkzbDqu4joIFpByEvcjbpL61YdCg1GYaXNbstqsYJ\n" +
             "mZHq5gII16bs3d48fBBt07rkDDyKVju01a9K0N32KzEEIRKn02WpsV/IAgetJFvb\n" +
             "S9fNRfrKCOebpqSTGbJFHmJYKX4vvzFDafC/c05BJ2isTHpGs4enEZ6UMjkGKSFm\n" +
             "JnTwCfN3VKMFHeocbQIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCAgQwDAYDVR0TBAUw\n" +
             "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFf6RWcp0f2Jl0dg66Jk8wq6FqsB4t9sO\n" +
             "aWIS7sn31awDvelLsuVo+cs5rDCCIH1mjrLp8uZsFDd+f5vaxDwDaMPCVnzSdEP1\n" +
             "nivS0GzFIS2XBC0OPl0pQbTy1bSZcfjBAGSCesWkuZBAkMcE+5/u2SKwCxb3b2Kw\n" +
             "JhSWZbiSwlMvM2bhoi46pcqQPaSKR76sWbXLJgwKYquEFpwkesh+mfenVegbv6mo\n" +
             "3+kefThDIvD1RPlWYinXOSvnOglrtJPYTUZtN1xth2GeKlwk7y4gXsRMZecPtngt\n" +
             "sXtZFlL87xFZL+Gn4ZXHNjaquv5o6RMJ0vW/kHFTIPEmaFc0YAOTRA==\n" +
             "-----END CERTIFICATE-----\n" ;
	
	public String sign(final String inputCSR, String privateKey )
	        throws Exception { 
		return sign(inputCSR, privateKey,null,null) ;
	}
	
	public String sign(final String inputCSR,String privateKey,String url, String ocspurl)
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
				
				is = new ByteArrayInputStream(intCA.trim().getBytes());
				isr = new InputStreamReader(is);
				br = new BufferedReader(isr);
				parser = new PEMParser(br);
				obj = parser.readObject();
				
				if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
					
					X509CertificateHolder certificateHolder = (X509CertificateHolder) obj;
					byte[] x509 = certificateHolder.getEncoded();
					CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
					X509Certificate cacert = (X509Certificate) certificateFactory
							.generateCertificate(new ByteArrayInputStream(x509));
					
					X509Certificate certificate = sign(certificationRequest, cacert , pk, kp,url,ocspurl);
					return Utils.toPem(certificate);
				}
			}
			throw new Exception("No Private Key Found in the System");
		}
		throw new Exception("Not a Valid CSR ");
	}
	
	
	
	private X509Certificate sign(PKCS10CertificationRequest inputCSR, X509Certificate caCert, PrivateKey caPrivate, KeyPair pair,String url, String ocspurl)
	        throws Exception {   
		
		X500NameBuilder x500NameBld = new X500NameBuilder(RFC4519Style.INSTANCE);
		x500NameBld.addRDN(RFC4519Style.cn, "8gwifi.org");
		X500Name subject = x500NameBld.build();
		
		PKCS10CertificationRequest pk10Holder = (PKCS10CertificationRequest)inputCSR;
		JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(pk10Holder);
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subject,
				Utils.getRandomBigInteger(), 
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000),
				jcaRequest.getSubject(),
				jcaRequest.getPublicKey());
       
				
				JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(
        		Extension.authorityKeyIdentifier,
        		false,
                extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(jcaRequest
                        .getPublicKey()))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, new KeyUsage(
                		KeyUsage.digitalSignature | 
                		KeyUsage.keyEncipherment ))
                .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caPrivate);
        
      //Add the CRL endpoint
        if(url!=null && url.length()>0 )
        {
        DistributionPointName crlEp = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName
                .uniformResourceIdentifier, url)));
        DistributionPoint disPoint = new DistributionPoint(crlEp, null, null);
        certificateBuilder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{disPoint}));
        }

        if(ocspurl!=null && ocspurl.length()>0)
        {
        //Add the OCSP endpoint
        AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspurl)
        );
        ASN1EncodableVector authInfoAccessASN = new ASN1EncodableVector();
        authInfoAccessASN.add(ocsp);
        certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(authInfoAccessASN));
        }

        

        //Add the OCSP endpoint
       
//        if(ocspurl!=null && ocspurl.length()>0)
//        {
//        DERSequence ocspname = new DERSequence(new ASN1Encodable[] {
//                new GeneralName(GeneralName.uniformResourceIdentifier, ocspurl)});
//        
//        AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
//                new GeneralName(GeneralName.uniformResourceIdentifier, ocspname)
//        );
//        ASN1EncodableVector authInfoAccessASN = new ASN1EncodableVector();
//        authInfoAccessASN.add(ocsp);
//        certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(authInfoAccessASN));
//        
//        }
                
        X509Certificate signedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate
                (certificateBuilder.build(signer));
        
        return signedCert;
		
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
	            new X500Name("CN=8gwifi.org"), Utils.getRandomBigInteger(), new Date(
	                    System.currentTimeMillis()), new Date(
	                    System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000), 
	                    pk10Holder.getSubject(), 
	                    keyInfo);
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
