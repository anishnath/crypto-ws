package cacerts;

import java.net.URL;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author anishnath
 *
 */

public class WebCerts {
	
	static {
        Security.addProvider(new BouncyCastleProvider());
    }
	
	public List<String>  getCerts(final String url, int port ) throws Exception
	{
		List<String> certList = new ArrayList<>();
		URL destinationURL = new URL("https",url,port,"/");
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.setConnectTimeout(10000);
        conn.connect();
		//System.out.println(conn);
		Certificate[] certs = conn.getServerCertificates();
        //System.out.println("nb = " + certs.length);
        int i = 1;
        for (Certificate cert : certs) {
        	 if(cert instanceof X509Certificate) {
        		 certList.add(Utils.toPem((X509Certificate)cert));
        	 }
        }
        return certList;
	}
	
	public static void main(String[] args) throws Exception {
		
		WebCerts certs = new WebCerts();
		System.out.println(certs.getCerts("fundingsocieties.com", 8443));
	}

}
