package cacerts;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;  
import org.bouncycastle.asn1.x509.BasicConstraints;  
import org.bouncycastle.asn1.x509.Extension;  
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;  
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;  
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;  
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.OperatorCreationException;  
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.joda.time.DateTime;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;  
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.math.BigInteger;  
import java.security.*;  
import java.security.cert.CertificateEncodingException;  
import java.security.cert.CertificateException;  
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;  

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.misc.IOUtils;
  
  
public class GenerateCACerts {  
	
	static {
        Security.addProvider(new BouncyCastleProvider());
    }
	
	private String algo="SHA256withRSA";
	private String dnsName="localhost.localdomain";
	int keysize=2048;
	
	public GenerateCACerts()
	{
		
	}
	
	public GenerateCACerts(String p_algo, String p_dnsName,int p_keysize)
	{
		this.algo=p_algo;
		this.dnsName=p_dnsName;
		this.keysize=p_keysize;
		
	}
	
	public GenerateCACerts(String p_dnsName){
		this.dnsName=p_dnsName;
	}
	
	public String decodeDERValue(byte[] value) { 
        ASN1InputStream vis = null; 
        ASN1InputStream decoded = null; 
        try { 
            vis = new ASN1InputStream(value); 
            decoded = new ASN1InputStream( 
                ((DEROctetString) vis.readObject()).getOctets()); 
 
            return decoded.readObject().toString(); 
        } 
        catch (IOException e) { 
            throw new RuntimeException(e); 
        } 
        finally { 
            if (vis != null) { 
                try { 
                    vis.close(); 
                } 
                catch (IOException e) { 
                    e.printStackTrace();
                } 
            } 
 
            if (decoded != null) { 
                try { 
                    decoded.close(); 
                } 
                catch (IOException e) { 
                	e.printStackTrace();
                } 
            } 
        } 
    } 
	
	private byte[] getPemEncoded(Object obj) throws IOException { 
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(); 
        OutputStreamWriter oswriter = new OutputStreamWriter(byteArrayOutputStream); 
        PEMWriter writer = new PEMWriter(oswriter); 
        writer.writeObject(obj); 
        writer.close(); 
        return byteArrayOutputStream.toByteArray(); 
    } 
	

    public byte[] getPemEncoded(Key key) throws IOException { 
        return getPemEncoded((Object) key); 
    } 
 
    
    public static String toPem(KeyPair keyPair) throws IOException {
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        try {
            pemWriter.writeObject(keyPair);
            pemWriter.flush();
            return writer.toString();
        } finally {
        	pemWriter.close();
        }
    }
    
    public static String toPem(PublicKey keyPair) throws IOException {
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        try {
            pemWriter.writeObject(keyPair);
            pemWriter.flush();
            return writer.toString();
        } finally {
        	pemWriter.close();
        }
    }
    
    public static String toPem(X509Certificate keyPair) throws IOException {
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        try {
            pemWriter.writeObject(keyPair);
            pemWriter.flush();
            return writer.toString();
        } finally {
        	pemWriter.close();
        }
    }
	
	
	public CAAuthorityPOJO generateCAAuthority(final String p_dnsName)
	{
		CAAuthorityPOJO authorityPOJO = new CAAuthorityPOJO();
		BASE64Encoder base64Encoder = new BASE64Encoder();
		try {
			// Create self signed Root CA certificate  
			KeyPair rootCAKeyPair = generateKeyPair();  
			X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(  
			    new X500Name("CN=rootCA"), // issuer authority  
			    BigInteger.valueOf(new Random().nextInt()), //serial number of certificate  
			    DateTime.now().toDate(), // start of validity  
			    new DateTime(2025, 12, 31, 0, 0, 0, 0).toDate(), //end of certificate validity  
			    new X500Name("CN=rootCA"), // subject name of certificate  
			    rootCAKeyPair.getPublic()); // public key of certificate  
			// key usage restrictions  
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
			builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));  
			X509Certificate rootCA = new JcaX509CertificateConverter().getCertificate(builder  
			    .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").  
			        build(rootCAKeyPair.getPrivate()))); // private key of signing authority , here it is self signed  
			
			//byte[] b = getPemEncoded(rootCAKeyPair.getPrivate());
			//RSA PRIVATE KEY
			
			//PemObject
			
			//System.out.println(toPem(rootCAKeyPair));
			//System.out.println(toPem(rootCA));
			
			//System.out.println(base64Encoder.encode(rootCAKeyPair.getPrivate().getEncoded()));
			authorityPOJO.setRootCAPrivateKey(toPem(rootCAKeyPair));
			authorityPOJO.setRootCAPubliceKey(toPem(rootCAKeyPair.getPublic()));	
			authorityPOJO.setRootCACerts(toPem(rootCA));
			
			
			
			
			//System.out.println(rootCA.getEncoded().toString());
			//saveToFile(rootCA, "D:\\rootCA.cer");  
  
  
			//create Intermediate CA cert signed by Root CA  
			KeyPair intermedCAKeyPair = generateKeyPair();  
			builder = new JcaX509v3CertificateBuilder(  
			    rootCA, // here rootCA is issuer authority  
			    BigInteger.valueOf(new Random().nextInt()), DateTime.now().toDate(),  
			    new DateTime(2025, 12, 31, 0, 0, 0, 0).toDate(),  
			    new X500Name("CN=IntermedCA"), intermedCAKeyPair.getPublic());  
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
			builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));  
			X509Certificate intermedCA = new JcaX509CertificateConverter().getCertificate(builder  
			    .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").  
			        build(rootCAKeyPair.getPrivate())));// private key of signing authority , here it is signed by rootCA  
			
			
			authorityPOJO.setInterCAPrivateKey(toPem(intermedCAKeyPair));
			authorityPOJO.setInterCAPubliceKey(toPem(intermedCAKeyPair.getPublic()));	
			authorityPOJO.setInterCACerts(toPem(intermedCA));
			
			//System.out.println(intermedCA.getEncoded().toString());
			//saveToFile(intermedCA, "D:\\intermedCA.cer");  
  
			//create end user cert signed by Intermediate CA  
			KeyPair endUserCertKeyPair = generateKeyPair();  
			builder = new JcaX509v3CertificateBuilder(  
			    intermedCA, //here intermedCA is issuer authority  
			    BigInteger.valueOf(new Random().nextInt()), DateTime.now().toDate(),  
			    new DateTime(2025, 12, 31, 0, 0, 0, 0).toDate(),  
			    new X500Name("CN="+p_dnsName + ""), endUserCertKeyPair.getPublic());  
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));  
			builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));  
			X509Certificate endUserCert = new JcaX509CertificateConverter().getCertificate(builder  
			    .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").  
			        build(intermedCAKeyPair.getPrivate())));// private key of signing authority , here it is signed by intermedCA  
			

			authorityPOJO.setDnsCerts(toPem(endUserCert));
			authorityPOJO.setDnsPrivateKey(toPem(endUserCertKeyPair));
			authorityPOJO.setDnsPubliceKey(toPem(endUserCertKeyPair.getPublic()));
			
			
		} catch (Exception ex ) 
		{
			return null;
		}
		
		return authorityPOJO;
		
	}
  
  public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException, InvalidKeyException, NoSuchProviderException, SignatureException, UnrecoverableKeyException {  
    
	  
	 System.out.println( new GenerateCACerts().generateCAAuthority("anish"));
    
  
    
    //saveToFile(endUserCert, "D:\\endUserCert.cer");  
  }  
  
  private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {  
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");  
    kpGen.initialize(2048, new SecureRandom());  
    return kpGen.generateKeyPair();  
  }  
  
  private static void saveToFile(X509Certificate certificate, String filePath) throws IOException, CertificateEncodingException {  
    FileOutputStream fileOutputStream = new FileOutputStream(filePath);  
    fileOutputStream.write(certificate.getEncoded());  
    fileOutputStream.flush();  
    fileOutputStream.close();  
  }  
  
}  
