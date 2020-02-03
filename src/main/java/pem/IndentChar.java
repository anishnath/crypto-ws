package pem;

public enum IndentChar {
	SPACE(' '), TAB('\t');

	private char indentChar;

	IndentChar(char indentChar) {
		this.indentChar = indentChar;
	}

	/**
	 * Get indentation character.
	 *
	 * @return Indentation character
	 */
	public char getIndentChar() {
		return indentChar;
	}

	@Override
	public String toString() {
		return String.valueOf(indentChar);
	}
}