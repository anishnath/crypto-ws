package pem;

public enum QcStatementType {

	// @formatter:off

	QC_SYNTAX_V1("1.3.6.1.5.5.7.11.1", "QCSyntaxV1"),
	QC_SYNTAX_V2("1.3.6.1.5.5.7.11.2", "QCSyntaxV2"),
	QC_COMPLIANCE("0.4.0.1862.1.1", "QCCompliance"),
	QC_EU_LIMIT_VALUE("0.4.0.1862.1.2", "QCEuLimitValue"),
	QC_RETENTION_PERIOD("0.4.0.1862.1.3", "QCRetentionPeriod"),
	QC_SSCD("0.4.0.1862.1.4", "QCSSCD"),
	QC_PDS("0.4.0.1862.1.5", "QCPDS"),
	QC_TYPE("0.4.0.1862.1.6", "QCType");

	// @formatter:on

	private String oid;
	private String friendlyKey;

	QcStatementType(String oid, String friendlyKey) {
		this.oid = oid;
		this.friendlyKey = friendlyKey;
	}

	/**
	 * Resolve the supplied object identifier to a matching type.
	 *
	 * @param oid
	 *            Object identifier
	 * @return Type or null if none
	 */
	public static QcStatementType resolveOid(String oid) {
		for (QcStatementType type : values()) {
			if (oid.equals(type.oid())) {
				return type;
			}
		}

		return null;
	}

	/**
	 * Get Access Method's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}

	/**
	 * Get friendly key for resource string
	 *
	 * @return Key for resource string
	 */
	public String getResKey() {
		return friendlyKey;
	}
}

