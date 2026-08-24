package burp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;

/** Lifecycle owner for the optional local Go core. Burp-facing code remains in Java. */
final class GoScannerProcess {
    private Process process;
    private Path directory;

    synchronized boolean start() {
        if (process != null && process.isAlive()) return true;
        String os = System.getProperty("os.name").toLowerCase();
        String platform = os.contains("win") ? "windows" : os.contains("mac") ? "darwin" : "linux";
        String arch = System.getProperty("os.arch").contains("64") && !System.getProperty("os.arch").contains("aarch") ? "amd64" : "arm64";
        String executable = "smugglerd" + (platform.equals("windows") ? ".exe" : "");
        String resource = "/native/" + platform + "-" + arch + "/" + executable;
        try (InputStream binary = getClass().getResourceAsStream(resource);
             InputStream checksum = getClass().getResourceAsStream(resource + ".sha256")) {
            if (binary == null || checksum == null) return false; // configured Java fallback
            directory = Files.createTempDirectory("http-request-smuggler-");
            Path target = directory.resolve(executable);
            byte[] bytes = binary.readAllBytes();
            String expected = new String(checksum.readAllBytes(), StandardCharsets.US_ASCII).trim();
            String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), actual.getBytes(StandardCharsets.US_ASCII))) throw new SecurityException("smugglerd checksum mismatch");
            Files.write(target, bytes);
            if (!platform.equals("windows")) Files.setPosixFilePermissions(target, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
            String token = HexFormat.of().formatHex(new SecureRandom().generateSeed(32));
            String network = platform.equals("windows") ? "tcp" : "unix";
            String address = platform.equals("windows") ? "127.0.0.1:0" : directory.resolve("smugglerd.sock").toString();
            process = new ProcessBuilder(target.toString(), "-network", network, "-address", address, "-token", token).redirectErrorStream(true).start();
            return true;
        } catch (Exception e) {
            stop();
            return false;
        }
    }

    synchronized void stop() {
        if (process != null) {
            process.destroy();
            try { if (!process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) process.destroyForcibly(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); process.destroyForcibly(); }
            process = null;
        }
        if (directory != null) {
            try (var paths = Files.walk(directory)) { paths.sorted(java.util.Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) {} }); }
            catch (IOException ignored) {}
            directory = null;
        }
    }
}
