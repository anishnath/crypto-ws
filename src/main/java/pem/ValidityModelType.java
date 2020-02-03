package pem;

import java.util.ResourceBundle;

/**
 *
 * Enumeration of Validity Models (1.3.6.1.5.5.7.1.1).
 *
 */
public enum ValidityModelType {
	CHAIN_MODEL("1.3.6.1.4.1.8301.3.5.1", "ChainModel"),
	SHELL_MODEL("1.3.6.1.4.1.8301.3.5.2", "ShellModel");

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/crypto/x509/resources");
	private String oid;
	private String friendlyKey;

	ValidityModelType(String oid, String friendlyKey) {
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
	public static ValidityModelType resolveOid(String oid) {
		for (ValidityModelType type : values()) {
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
}