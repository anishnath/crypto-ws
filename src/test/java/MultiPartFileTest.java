import java.io.File;
import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

public class MultiPartFileTest {
	
	public static void main(String[] args) throws ClientProtocolException, IOException {
		HttpClient httpclient = new DefaultHttpClient();
		HttpPost httpPost = new HttpPost("http://localhost:8082/crypto/rest/dsa/sign");

		FileBody uploadFilePart = new FileBody(new File("pom.xml.asc"));
		FileBody uploadFilePart2 = new FileBody(new File("pubkey.asc"));
		
		
		StringBody stringBody  = new StringBody("test...");
		
		MultipartEntity reqEntity = new MultipartEntity();
		reqEntity.addPart("p_file", uploadFilePart);
		reqEntity.addPart("p_key", stringBody);
		reqEntity.addPart("p_algo", stringBody);
		httpPost.setEntity(reqEntity);

		HttpResponse response = httpclient.execute(httpPost);
		String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
		
		System.out.println(responseString);
	}

}
