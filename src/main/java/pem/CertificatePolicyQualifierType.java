package pem;
import java.util.ResourceBundle;

public enum CertificatePolicyQualifierType {

	// @formatter:off

	PKIX_CPS_POINTER_QUALIFIER("1.3.6.1.5.5.7.2.1", "PkixCpsPointerQualifier"),
	PKIX_USER_NOTICE_QUALIFIER("1.3.6.1.5.5.7.2.2", "PkixUserNoticeQualifier");

	// @formatter:on

	private static ResourceBundle res = ResourceBundle.getBundle("pem/resources");
	private String oid;
	private String friendlyKey;

	CertificatePolicyQualifierType(String oid, String friendlyKey) {
		this.oid = oid;
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Get type's friendly name.
	 *
	 * @return Friendly name
	 */
	public String friendly() {
		return res.getString(friendlyKey);
	}

	/**
	 * Resolve the supplied object identifier to a matching type.
	 *
	 * @param oid
	 *            Object identifier
	 * @return Type or null if none
	 */
	public static CertificatePolicyQualifierType resolveOid(String oid) {
		for (CertificatePolicyQualifierType type : values()) {
			if (oid.equals(type.oid())) {
				return type;
			}
		}

		return null;
	}

	/**
	 * Get Certificate Policy Qualifier's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}
}
