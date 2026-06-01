package ssh;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * SSH key-format converter.
 *
 * Pure string-in / string-out transformations that wrap the system {@code puttygen}
 * (and optionally {@code ssh-keygen -m PEM}) binaries. Designed to be called
 * downstream of {@link SSHKeyGen} — give it a private key in any format the
 * server already produces and get back a PPK (or PEM).
 *
 * Verified compatible input formats (puttygen 0.76+):
 *   • PKCS#1 PEM         {@code -----BEGIN RSA/DSA/EC PRIVATE KEY-----}  (what JSch emits)
 *   • OpenSSH private    {@code -----BEGIN OPENSSH PRIVATE KEY-----}     (what ssh-keygen emits)
 *
 * NOT compatible:
 *   • PKCS#8 PEM         {@code -----BEGIN PRIVATE KEY-----}             (the legacy
 *     {@code generateEd25519Keypair} pure-Java path produced this; that path is
 *     not invoked in production today.)
 *
 * Security posture (mirrors patterns already in {@link SSHKeyGen}):
 *   • Temp files under {@code java.io.tmpdir} with random UUID names.
 *   • {@code ProcessBuilder} with explicit argv — no shell interpretation.
 *   • Passphrase passed via a separate temp file with permissions 0600.
 *   • 10-second hard timeout on the spawned process.
 *   • All temp files deleted in a {@code finally} block (best-effort).
 *
 * @author Anish Nath
 * Demo @ https://8gwifi.org
 */
public class SSHKeyConvert {

    /** Default PPK output version. v3 (Argon2 KDF) is the modern PuTTY 0.75+ default. */
    public static final int DEFAULT_PPK_VERSION = 3;

    /** Hard cap on how long puttygen / ssh-keygen may run. */
    private static final int PROCESS_TIMEOUT_SECONDS = 10;

    /**
     * Convert an existing private key (PKCS#1 or OpenSSH-format PEM) to PuTTY's
     * {@code .ppk} format. The output is encrypted with the same passphrase as
     * the input — puttygen carries it through automatically.
     *
     * @param privateKey      armored private key text as produced by SSHKeyGen
     * @param passphrase      passphrase the key was encrypted with, or null/empty if unencrypted
     * @param ppkVersion      2 or 3 (default 3 — see {@link #DEFAULT_PPK_VERSION})
     * @return PPK-formatted private key as a string
     * @throws KeyConvertException if puttygen is missing, the passphrase is wrong, or the
     *                             format is unrecognised
     */
    public static String toPpk(String privateKey, String passphrase, int ppkVersion) throws KeyConvertException {
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw new KeyConvertException("Empty private key input");
        }
        if (ppkVersion != 2 && ppkVersion != 3) {
            ppkVersion = DEFAULT_PPK_VERSION;
        }

        String tmpDir = System.getProperty("java.io.tmpdir");
        String base   = tmpDir + "/" + UUID.randomUUID();
        File privFile = new File(base);
        File ppkFile  = new File(base + ".ppk");
        File passFile = null;

        try {
            writeKeyFile(privFile, privateKey);

            List<String> cmd = new ArrayList<>();
            cmd.add("puttygen");
            cmd.add(privFile.getAbsolutePath());
            cmd.add("-o");
            cmd.add(ppkFile.getAbsolutePath());
            cmd.add("--ppk-param");
            cmd.add("version=" + ppkVersion);

            if (passphrase != null && !passphrase.isEmpty()) {
                passFile = writePassphraseFile(passphrase, base + ".pp");
                cmd.add("--old-passphrase");
                cmd.add(passFile.getAbsolutePath());
            }

            runProcess(cmd, "puttygen");

            if (!ppkFile.exists()) {
                throw new KeyConvertException("puttygen produced no output (input format may be unsupported)");
            }
            return new String(Files.readAllBytes(Paths.get(ppkFile.getAbsolutePath())), StandardCharsets.UTF_8);

        } catch (IOException ioe) {
            throw new KeyConvertException("I/O failure during PPK conversion: " + ioe.getMessage(), ioe);
        } finally {
            cleanupFiles(privFile, ppkFile, passFile);
        }
    }

    /** Convenience overload using {@link #DEFAULT_PPK_VERSION}. */
    public static String toPpk(String privateKey, String passphrase) throws KeyConvertException {
        return toPpk(privateKey, passphrase, DEFAULT_PPK_VERSION);
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static void writeKeyFile(File f, String contents) throws IOException {
        Files.write(f.toPath(), contents.getBytes(StandardCharsets.UTF_8));
        // POSIX 0600 — best effort; ignored on non-POSIX FS
        try {
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(
                    f.toPath(),
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystem (e.g. Windows); best-effort permissions only.
        }
    }

    private static File writePassphraseFile(String pass, String path) throws IOException {
        File f = new File(path);
        // puttygen reads the entire file content (minus a trailing newline)
        // as the passphrase. Match that contract.
        Files.write(f.toPath(), (pass + "\n").getBytes(StandardCharsets.UTF_8));
        try {
            Files.setPosixFilePermissions(
                    f.toPath(),
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
        }
        return f;
    }

    /**
     * Runs the given command with explicit argv. Captures stderr so we can surface
     * meaningful error messages ("decryption check failed", "unrecognised key type").
     */
    private static void runProcess(List<String> cmd, String toolLabel) throws KeyConvertException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process pr;
        try {
            pr = pb.start();
        } catch (IOException e) {
            throw new KeyConvertException(
                    toolLabel + " not found in PATH. Install putty-tools and ensure "
                    + toolLabel + " is reachable for the service user.");
        }
        try {
            boolean finished = pr.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                pr.destroyForcibly();
                throw new KeyConvertException(toolLabel + " timed out after " + PROCESS_TIMEOUT_SECONDS + "s");
            }
            int rc = pr.exitValue();
            if (rc != 0) {
                String err = readStreamSafely(pr.getErrorStream());
                throw new KeyConvertException(classifyError(toolLabel, err));
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            pr.destroyForcibly();
            throw new KeyConvertException(toolLabel + " interrupted");
        } finally {
            closeQuietly(pr.getInputStream());
            closeQuietly(pr.getErrorStream());
            closeQuietly(pr.getOutputStream());
        }
    }

    /** Map puttygen's stderr to a friendlier error class. */
    private static String classifyError(String toolLabel, String stderr) {
        String s = stderr == null ? "" : stderr.toLowerCase();
        if (s.contains("decryption check failed") || s.contains("incorrect passphrase")) {
            return "Incorrect passphrase for the input key";
        }
        if (s.contains("unrecognised key type") || s.contains("unable to identify")) {
            return "Input key format not supported by puttygen (expected PKCS#1 or OpenSSH PEM)";
        }
        if (s.contains("no such file")) {
            return "Internal error: input file disappeared before " + toolLabel + " could read it";
        }
        // Surface raw stderr trimmed — useful for diagnosing edge cases without leaking key material
        return toolLabel + " failed: " + (stderr == null ? "(no stderr)" : stderr.trim());
    }

    private static String readStreamSafely(InputStream in) {
        if (in == null) return "";
        try {
            byte[] buf = new byte[4096];
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "(unable to read stderr: " + e.getMessage() + ")";
        }
    }

    private static void cleanupFiles(File... files) {
        for (File f : files) {
            if (f == null) continue;
            try { f.delete(); } catch (Exception ignored) {}
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (Exception ignored) {}
    }

    /** Conversion-specific exception so callers can distinguish from generic IOErrors. */
    public static class KeyConvertException extends Exception {
        public KeyConvertException(String message) { super(message); }
        public KeyConvertException(String message, Throwable cause) { super(message, cause); }
    }

    // ─── CLI for manual testing ────────────────────────────────────────────
    // Usage: java ssh.SSHKeyConvert <private-key-file> [passphrase]
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java ssh.SSHKeyConvert <private-key-file> [passphrase]");
            System.exit(2);
        }
        String key = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
        String pass = args.length > 1 ? args[1] : "";
        try {
            String ppk = toPpk(key, pass);
            System.out.println(ppk);
        } catch (KeyConvertException e) {
            System.err.println("CONVERT FAILED: " + e.getMessage());
            System.exit(1);
        }
    }
}
