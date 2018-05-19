package crack;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;


/**
 * 
 * @author Anish Nath For Demo Visit https://8gwifi.org
 *
 */

public class EncryptedPemCracker {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static int MAX_PASSWORDS = 1000;

	final static String default_password = "123456,Password,Unchanged,12345678, qwerty, 12345, 123456789,letmein, 1234567, football, iloveyou, admin, welcome, monkey, login, abc123, starwars,123123, dragon, passw0rd, master, hello, freedom, whatever, qazwsx, trustno1, 654321,jordan23, harley, password1, 1234, robert, matthew, jordan, asshole, daniel,hello123";

	public String crack(String fileName, String passwords) throws Exception {
		
		if (null == fileName || fileName.trim().length() == 0) {
			throw new Exception("Please provide a Encrypted PEM File");
		}

		if (!fileName.contains("ENCRYPTED")) {
			throw new Exception("Please provide Valid Encrypted PEM File");
		}
		
		boolean isFound=false;
		String passwordFound=null;
		
		if(null==passwords || passwords.trim().length()==0)
		{
			passwords=default_password;
		}
		
		
		BufferedReader bufReader = new BufferedReader(new StringReader(passwords));
		Set<String> passwordSet = new HashSet<String>();
		String line = null;
		try {
			while ((line = bufReader.readLine()) != null) {
				line = line.trim();
				String[] myData = line.split(",");
				for (String s : myData) {
					s = s.trim();
					passwordSet.add(s);
					if (passwordSet.size() > MAX_PASSWORDS) {
						throw new Exception("Max Supported Password limit is 1000");
					}
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] content = fileName.trim().getBytes();
		InputStream is = new ByteArrayInputStream(content);
		InputStreamReader isr = new InputStreamReader(is);

		Reader br = new BufferedReader(isr);

		PEMParser parser = new PEMParser(br);

		Object obj = parser.readObject();
		
		for (Iterator iterator = passwordSet.iterator(); iterator.hasNext();) {
			String string = (String) iterator.next();
			
			try {
				if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
					PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) obj;

					InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
							.build(string.toCharArray());
					PrivateKeyInfo privateKeyinfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
					isFound=true;
					passwordFound=string;
					break;
					
				}
			} catch (Exception e) {
				
			}
			
			try {
				if (obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
					PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
					PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(string.toCharArray());
					PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decProv);
					isFound=true;
					passwordFound=string;
					break;
				}
			} catch (Exception e) {
				
			}

		}
		
		if(isFound)
		{
			return passwordFound;
		}
		else 
		{
			return null;
		}

	}
	
	public static void main(String[] args) throws Exception {
		EncryptedPemCracker cracker = new EncryptedPemCracker();
		
		String s = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "Proc-Type: 4,ENCRYPTED\n" +
                "DEK-Info: DES-EDE3-CBC,DD02A2C199E64A02\n" +
                "\n" +
                "oCmw6ivfpvH522PseAre82sBsN37t9eR1pxoHiOQk1HP7Tr+ppheE9PwkJkfwdtC\n" +
                "dE1aTbuqE84cvXIl+P/C6RmsXhS3dkY3Sj83y55rARO8qIQWtVmtWA/njDsiMoxt\n" +
                "6iaCfEhPwESpu9PLVVpc3JfO2ntLrr/xcp4dnfHSPnN8UWbcnLhyWV1cFTiXHY9S\n" +
                "0tPghp1gxnQzrDNLcGVj+CK+nZBaXFQEt7be7bJWIuVTliC+jfI5J/nWo1T81u2O\n" +
                "0DBFYe4ieQt+JJPuNLg6/hcUcikaDlP7ERIxpndymx5c5mf7VYGiI3sPDMnW1QCX\n" +
                "PxrZb1mMrsLJKGTJLfmkRrE1dBKIm7ZWDMRYHeJqUq1QhCdpaH5NVrkaC6TouQw9\n" +
                "FBG2KHxcX7JLYTHk4zwHtg35/mUR77nZD1hGZjEM7nHPnZJ6IrglEd/VzhuIK/oT\n" +
                "uM4YZ7L/uuQho15Aso+Fqx0hsVLebtRWVEIHdf+JPhKGmoWcc1I8NABkh80O0IXm\n" +
                "UWoIZv7tkrNVIXWhKohGvifxIs210nUGDcicwqq5CeNBPniR9M4tzGnj3PSnfjNx\n" +
                "XFDINJInfRjtslm1uv+Jb0VLpZbimJ92U+66Kvfr6sk1fR70kp2lo8Q3UY90X+0U\n" +
                "+VOpZ8zYGsTBYcs9BNiuBxT8P8eTWZTXBuHFiubw3HestkwX2h6kiEnNS/TEgFT8\n" +
                "cvFKcdwATgAYInngEuXp61hErjfEEvQ1GStzLaidQqrU9wioggaJacu1iWTbVca8\n" +
                "x0yroqYmQ+bs6pq4im5+jqnjdsABWVXDaPZO/imWjc5wLVNZpqCFuATRAY/mgOY9\n" +
                "T9a7w1t/yfIW6XlrRmTTgbP8H2DoOjZ7sS6Sd5woulh0tsQF9qJVxhMc88Uac1vW\n" +
                "+rMZwEqX0Egcv7lVT16EtEkabiFGqXs2EPng7dtgA+SRoh1QDNUKLmTdJ5eKAND0\n" +
                "vtgUikfuUIZrOIZUYyyHECurv85WKqKDWE5k5KBZwsxQGrKRHPmCkCWVjtDRWpBq\n" +
                "ZySZiuIwr/UggtDKqgprsIfmipxnaLwdsKS0OXE7YFly6XJab2IztYA91Y5LZEHM\n" +
                "VqVAHoV+O2qR9lmnXcFIg0KkLHDzEuOEzRnrcWcOE0JHfgBOs+xZyiJmiHvtgOGT\n" +
                "Lsd4DZbBE8XiSkshcgF5CjVo4kW5UIgOyJpNmMiEnFXHAaR0Xc0DBrcjiWNhxOAJ\n" +
                "E73pQ2pDTTr0RrY4VDGceFfvo8osqkuEZiPYB7rGMveG7EcyxKagXI6A0EWust0i\n" +
                "Z/4Ex7+vo9nryn6mRTV4R1FGf92noOu0xnmNYfh0SxyGFaCJgT9BSaZBWntT/mY/\n" +
                "MdTqVtEmZM4pAows7jouwpHyYmJO6FwK7aF2bV3lcnYbz/rNlf7AYekfzKcCA/0p\n" +
                "FXV3cUWNq9q4WNP4R5k9eoBOAUYirtXzj8xrASMMMI1LSB6r3Rho8v7CmGG87GYs\n" +
                "hq1wskZ7kcUy1gAQ4OV3ckg4oJxINZ4UcfrgJRTntAMWVYEfOm7J7gr13tMzXrN5\n" +
                "u1vC96gNbxtLjR/s2XQoWn4EWy5l4J4CfUfGgOHsxMGPnCpYQukvdc09VcmYTPcq\n" +
                "-----END RSA PRIVATE KEY-----";
		
		String passwrds = "anish\n"+"test123,hellp,hello123";
		System.out.println(passwrds);
		String foundPasssrod = cracker.crack(s, null);
		
		System.out.println(foundPasssrod);
	}

}
