import java.io.Console;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class PasswordCreationAndVerification {

    public static final int SALT_LENGTH = 16; // bytes

    static final class StoredPassword {
        private final byte[] passwordHash;
        private final byte[] salt;
        private final int iterationCount;
        private final int parallelism;
        private final int memory;

        public StoredPassword(byte[] passwordHash, byte[] salt, int iterationCount, int parallelism, int memory) {
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.iterationCount = iterationCount;
            this.parallelism = parallelism;
            this.memory = memory;
        }

        public byte[] getPasswordHash() {
            return passwordHash;
        }

        public byte[] getSalt() {
            return salt;
        }

        public int getIterationCount() {
            return iterationCount;

        }

        public int getParallelism() {
            return parallelism;
        }

        public int getMemory() {
            return memory;
        }

        public String toString() {
            return "StoredPassword{" +
                    "passwordHash=" + bytesToHex(passwordHash) +
                    ", salt=" + bytesToHex(salt) +
                    ", iterationCount=" + iterationCount +
                    ", parallelism=" + parallelism +
                    ", memory=" + memory +
                    '}';
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString();
    }

    public static StoredPassword storePassword(char[] password) throws NoSuchAlgorithmException {
        byte[] salt = generateSalt(SALT_LENGTH);
        int iterationCount = 3;
        int parallelism = 4;
        int memory = 65536;
        byte[] passwordHash = hashPassword(password, salt, iterationCount, parallelism, memory);
        return new StoredPassword(passwordHash, salt, iterationCount, parallelism, memory);
    }

    public static byte[] hashPassword(char[] password, byte[] salt, int iterationCount, int parallelism, int memory)
            throws NoSuchAlgorithmException {

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterationCount)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] hash = new byte[32];
        generator.generateBytes(password, hash);

        return hash;
    }

    public static byte[] generateSalt(int length) {

        byte[] salt = new byte[length];

        (new SecureRandom()).nextBytes(salt);

        return salt;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        char[] originalPassword = new char[] { 'm', 'y', 's', 'e', 'c', 'r', 'e', 't' };
        StoredPassword sb = storePassword(originalPassword);
        Arrays.fill(originalPassword, '\0');

        Console console = System.console();

        if (console == null) {
            throw new RuntimeException("Console not available");
        }

        String line;
        do {
            char[] password = console.readPassword("Enter password: ");
            boolean result = verify(password, sb);
            Arrays.fill(password, '\0');
            System.out.println("Password verification result: " + result);
            line = console.readLine("Do you want to continue? (y/n)");            
        } while (line != null && "y".equalsIgnoreCase(line.trim()));

    

    }

    public static boolean verify(char[] password, StoredPassword sp) throws NoSuchAlgorithmException {
        byte[] passwordHash = hashPassword(password, sp.getSalt(), sp.getIterationCount(), sp.getParallelism(), sp.getMemory());
        return Arrays.equals(sp.getPasswordHash(), passwordHash);
    }
}
