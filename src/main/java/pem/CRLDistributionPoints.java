package pem;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DistributionPoint;

/**
 * X509 extension CRLDistributionPoints, RFC 5280
 *
 * <pre>
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * </pre>
 *
 */
public class CRLDistributionPoints extends ASN1Object {

	List<DistributionPoint> distributionPointList;

	/**
	 * Create an new CRLDistributionPoints object from given distribution
	 * points.
	 */
	public CRLDistributionPoints(List<DistributionPoint> distributionPointList) {
		this.distributionPointList = distributionPointList;
	}

	public static CRLDistributionPoints getInstance(Object obj) {
		if (obj instanceof CRLDistributionPoints) {
			return (CRLDistributionPoints) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CRLDistributionPoints((ASN1Sequence) obj);
		} else if (obj instanceof byte[]) {
			return new CRLDistributionPoints(ASN1Sequence.getInstance(obj));
		}

		throw new IllegalArgumentException("unknown object type");
	}

	private CRLDistributionPoints(ASN1Sequence seq) {
		distributionPointList = new ArrayList<DistributionPoint>();
		for (int i = 0; i != seq.size(); i++) {
			distributionPointList.add(DistributionPoint.getInstance(seq.getObjectAt(i)));
		}
	}

	/**
	 * Returns the distribution points making up the sequence.
	 */
	public List<DistributionPoint> getDistributionPointList() {
		return distributionPointList;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		Iterator<DistributionPoint> it = distributionPointList.iterator();
		while (it.hasNext()) {
			v.add(it.next().toASN1Primitive());
		}
		return new DERSequence(v);
	}
}
