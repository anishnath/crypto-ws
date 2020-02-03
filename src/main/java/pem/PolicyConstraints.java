package pem;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * PolicyConstraints from RFC 5280
 *
 * <pre>
 * PolicyConstraints ::= SEQUENCE {
 *     requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *     inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 *
 */
public class PolicyConstraints extends ASN1Object {

	int requireExplicitPolicy = -1;
	int inhibitPolicyMapping = -1;

	public static PolicyConstraints getInstance(Object obj){
		if(obj instanceof PolicyConstraints){
			return (PolicyConstraints)obj;
		}
		if(obj instanceof ASN1Sequence){
			return new PolicyConstraints((ASN1Sequence)obj);
		}
		if (obj instanceof byte[]) {
			return new PolicyConstraints(ASN1Sequence.getInstance(obj));
		}
		throw new IllegalArgumentException("invalid sequence");
	}

	private PolicyConstraints(ASN1Sequence seq) {
		if (seq.size() > 2) {
			throw new IllegalArgumentException("sequence length > 2");
		}

		for (int i = 0; i < seq.size(); i++) {
			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			switch (taggedObj.getTagNo()) {
			case 0:
				requireExplicitPolicy = ASN1Integer.getInstance(taggedObj.getObject()).getValue().intValue();
				break;
			case 1:
				inhibitPolicyMapping = ASN1Integer.getInstance(taggedObj.getObject()).getValue().intValue();
				break;
			default:
				throw new IllegalArgumentException("wrong tag number");
			}
		}
	}

	/**
	 * Creates a new PolicyConstraints object with the given
	 * requireExplicitPolicy and inhibitPolicyMapping.
	 */
	public PolicyConstraints(int requireExplicitPolicy, int inhibitPolicyMapping) {
		this.requireExplicitPolicy = requireExplicitPolicy;
		this.inhibitPolicyMapping = inhibitPolicyMapping;
	}

	public int getRequireExplicitPolicy() {
		return requireExplicitPolicy;
	}

	public int getInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}


	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();

		if (requireExplicitPolicy != -1) {
			vec.add(new DERTaggedObject(0, new ASN1Integer(requireExplicitPolicy)));
		}

		if (inhibitPolicyMapping != -1) {
			vec.add(new DERTaggedObject(1, new ASN1Integer(inhibitPolicyMapping)));
		}

		return new DERSequence(vec);
	}
}
