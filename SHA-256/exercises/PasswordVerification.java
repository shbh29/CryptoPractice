import java.security.*;
import java.util.*;

public class PasswordVerification {
    private static class StoredPassword {
        private byte[] password;
        private byte[] salt;

        public StoredPassword(byte[] salt, byte[] password) {
            this.salt = salt;
            this.password = password;
        }

        public byte[] getSalt() {
            return salt;
        }

        public byte[] getPassword() {
            return this.password;
        }

        public String toString() {
            return "StoredPassword{" +
                    "password='" + bytesToHex(password) + '\'' +
                    ", salt='" + bytesToHex(salt) + '\'' +
                    '}';
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    public static StoredPassword storePassword(String password) {
        // generate a random 16-byte salt
        byte[] salt = generateSalt(16);
        byte[] passwordHash = hashPassword(password, salt);
        return new StoredPassword(salt, passwordHash);
    }

    public static byte[] hashPassword(String password, byte[] salt) {
        // create a MessageDigest instance
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // update the digest with the password and salt
        md.update(password.getBytes());
        md.update(salt);
        // get the hash
        byte[] hash = md.digest();
        // print the hash
        System.out.println("Hash: " + bytesToHex(hash));
        return hash;
    }

    public static byte[] generateSalt(int length) {
        // generate a SecureRandom instance
        SecureRandom random = new SecureRandom();
        // generate a random salt
        byte[] salt = new byte[length];
        random.nextBytes(salt);
        // print the salt
        System.out.println("Salt: " + bytesToHex(salt));
        return salt;
    }

    public static boolean verify(String password, StoredPassword storedPassword) {
        byte[] inputHash = hashPassword(password, storedPassword.getSalt());
        return Arrays.equals(inputHash, storedPassword.getPassword());
    }


    public static void main(String[] args) {
        // new StoredPassword("mysecret");
        StoredPassword correctPassword = storePassword("mysecret");

        // test cases
        String userPassword = args[0];
        boolean result = verify(userPassword, correctPassword);
        System.out.println("Password is correct: " + result);
    }
}
