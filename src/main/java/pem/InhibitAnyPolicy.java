package pem;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * InhibitAnyPolicy extension from RFC 5280.
 *
 * <pre>
 * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 *
 */
public class InhibitAnyPolicy extends ASN1Object {

	int skipCerts;

	/**
	 * Creates an new instance with the given skipCerts.
	 */
	public InhibitAnyPolicy(int skipCerts) {
		this.skipCerts = skipCerts;
	}

	/**
	 * Returns the value of skipCerts.
	 */
	public int getSkipCerts(){
		return skipCerts;
	}

	public static InhibitAnyPolicy getInstance(Object obj) {
		if (obj instanceof InhibitAnyPolicy) {
			return (InhibitAnyPolicy) obj;
		}
		if (obj instanceof ASN1Integer) {
			int skipCerts = ((ASN1Integer) obj).getValue().intValue();
			return new InhibitAnyPolicy(skipCerts);
		}
		if (obj instanceof byte[]) {
			int skipCerts = ASN1Integer.getInstance(obj).getValue().intValue();
			return new InhibitAnyPolicy(skipCerts);
		}
		throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new ASN1Integer(skipCerts);
	}
}
