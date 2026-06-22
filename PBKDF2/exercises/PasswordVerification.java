import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.io.Console;



public class PasswordVerification {

    static class StoredPassword {
        final private byte[] salt;
        final private byte[] passwordHash;
        final private int iterations;
        
        public StoredPassword(byte[] salt, byte[] passwordHash, int iterations) {
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.iterations = iterations;
        }
        public byte[] getSalt() {
            return salt;
        }
        public byte[] getPasswordHash() {
            return passwordHash;
        }
        public int getIterations() {
            return iterations;
        }

        public String toString() {
            return "StoredPassword{" +
                    "salt=" + bytesToHex(salt) +
                    ", passwordHash=" + bytesToHex(passwordHash) +
                    ", iterations=" + iterations +
                    '}';
        }

    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for( byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString();
    }

    public static StoredPassword storePassword(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // generate a random salt
        byte[] salt = generateSalt(16);
        int iterations = 100000;
        int hashStringLength = 128;
        System.out.println("Salt: " + bytesToHex(salt));
        // hash the password with the salt
        byte[] passwordHash = hashPassword(password, salt, iterations, hashStringLength);
        System.out.println("Password hash: " + bytesToHex(passwordHash));    
        return new StoredPassword(salt, passwordHash, iterations);
    }

    public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int hashStringLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeSpec = null;
        try {
            pbeSpec = new PBEKeySpec(password, salt, iterations, hashStringLength);

            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeSpec).getEncoded();
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }

            if (pbeSpec != null) {
                pbeSpec.clearPassword();
            }
        }
    }

    public static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        (new SecureRandom()).nextBytes(salt);
        return salt;
    }

    public static void main(String... args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        StoredPassword sp = storePassword("mysecret".toCharArray());

        char[] userPassword = acceptPassword("Enter your password: ");

        try {
            boolean result = verify(userPassword, sp);
            System.out.println("Password verification result: " + result);
        } finally {
            Arrays.fill(userPassword, '\0');
        }
    }

    public static char[] acceptPassword(String prompt) throws IOException {
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available");
            System.exit(1);
        }

        return console.readPassword(prompt);
    }

    public static boolean verify(char[] password, StoredPassword sp) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] userPasswordHash = hashPassword(password, sp.getSalt(), sp.getIterations(), 128);
        System.out.println("User password hash: " + bytesToHex(userPasswordHash));
        return Arrays.equals(userPasswordHash, sp.getPasswordHash());
    }
}
