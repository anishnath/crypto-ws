package pem;

public class IndentSequence {
	public static final IndentSequence FOUR_SPACES = new IndentSequence(IndentChar.SPACE, 4);
	public static final IndentSequence SINGLE_TAB = new IndentSequence(IndentChar.TAB, 1);

	private IndentChar indentChar;

	private int indentSize;
	/**
	 * Construct IndentSequence.
	 *
	 * @param indentChar
	 *            Indent character
	 * @param indentSize
	 *            Indent size
	 */
	public IndentSequence(IndentChar indentChar, int indentSize) {
		this.indentChar = indentChar;
		this.indentSize = indentSize;
	}

	/**
	 * Get indent sequence for level.
	 *
	 * @param level
	 *            Indent level
	 * @return Indent sequence for level
	 */
	public String toString(int level) {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < level; i++) {
			sb.append(toString());
		}

		return sb.toString();
	}

	/**
	 * Get indent sequence.
	 *
	 * @return Indent sequence
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < indentSize; i++) {
			sb.append(indentChar.getIndentChar());
		}

		return sb.toString();
	}

	/**
	 * Get the indent character.
	 *
	 * @return
	 */
	public IndentChar getIndentChar() {
		return indentChar;
	}
}
