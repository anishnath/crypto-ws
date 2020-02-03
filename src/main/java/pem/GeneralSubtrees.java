package pem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralSubtree;

/**
 * Implements <code>GeneralSubtrees</code> from RFC 5280:
 * <pre>
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 * </pre>
 *
 */
public class GeneralSubtrees implements ASN1Encodable {

	private List<GeneralSubtree> subtrees;

	/**
	 * Create <code>GeneralSubtrees</code> from list of <code>GeneralSubtree</code>
	 * objects.
	 *
	 * @param subtrees
	 */
	public GeneralSubtrees(List<GeneralSubtree> subtrees) {
		this.subtrees = subtrees;
	}

	/**
	 * Create <code>GeneralSubtrees</code> from array of <code>GeneralSubtree</code>
	 * objects.
	 *
	 * @param subtrees
	 */
	public GeneralSubtrees(GeneralSubtree[] subtrees) {
		this.subtrees = new ArrayList<GeneralSubtree>(Arrays.asList(subtrees));
	}

	private GeneralSubtrees(ASN1Sequence seq) {
		subtrees = new ArrayList<GeneralSubtree>();
		for (int i = 0; i < seq.size(); i++) {
			subtrees.add(GeneralSubtree.getInstance(seq.getObjectAt(i)));
		}
	}

	public static GeneralSubtrees getInstance(Object obj) {
		if (obj instanceof GeneralSubtrees) {
			return (GeneralSubtrees) obj;
		}
		if (obj instanceof ASN1Sequence) {
			return new GeneralSubtrees((ASN1Sequence) obj);
		}
		throw new IllegalArgumentException("invalid ASN1Sequence");
	}

	public List<GeneralSubtree> getGeneralSubtrees() {
		return subtrees;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		for (int i = 0; i < subtrees.size(); i++) {
			vec.add(subtrees.get(i));
		}
		return new DERSequence(vec);
	}

}