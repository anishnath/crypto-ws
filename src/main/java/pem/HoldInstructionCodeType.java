package pem;

import java.util.ResourceBundle;

/**
 *
 * Enumeration of Hold Instruction Codes (2.5.29.23).
 *
 */
public enum HoldInstructionCodeType {
	NONE("1.2.840.10040.2.1", "HoldInstructionCodeNone"), CALL_ISSUER("1.2.840.10040.2.2",
			"HoldInstructionCodeCallIssuer"), CODE_REJECT("1.2.840.10040.2.3", "HoldInstructionCodeReject");

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private String oid;
	private String friendlyKey;

	HoldInstructionCodeType(String oid, String friendlyKey) {
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
	public static HoldInstructionCodeType resolveOid(String oid) {
		for (HoldInstructionCodeType type : values()) {
			if (oid.equals(type.oid())) {
				return type;
			}
		}

		return null;
	}

	/**
	 * Get Hold Instruction Code's Object Identifier.
	 *
	 * @return Object Identifier
	 */
	public String oid() {
		return oid;
	}
}
