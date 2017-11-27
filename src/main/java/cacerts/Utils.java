package cacerts;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMWriter;

/**
 * 
 * @author Anish Nath
 * For Demo Visit https://8gwifi.org
 *
 */

public class Utils {
	
	public static byte[] inputStreamToByteArray(InputStream is) throws IOException{

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[1024];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();
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
    
    public static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}
	
}
