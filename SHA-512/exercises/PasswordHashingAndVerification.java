import java.security.*;
import java.util.*;
import java.io.*;

public class PasswordHashingAndVerification {

    static class StoredPassword {
        byte[] pwHash;
        byte[] salt;

        public StoredPassword(byte[] salt, byte[] pwHash) {
            this.salt = salt;
            this.pwHash = pwHash;
        }

        public byte[] getSalt() {
            return salt;
        }

        public byte[] getPwHash() {
            return pwHash;
        }

        public String toString() {
            return "StoredPassword{" +
            "pwHash='" + bytesToHex(pwHash) + '\'' +
            ", salt='" + bytesToHex(salt) + '\'' +
            '}';
        }
    }


    public static StoredPassword storePassword(String password) throws NoSuchAlgorithmException {
        byte[] salt = generateSalt(16);
        byte[] pwHash = hashPassword(password, salt);
        return new StoredPassword(salt, pwHash);
    }

    public static byte[] hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        // create a MessageDigest instance
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        }
        md.update(password.getBytes());
        md.update(salt);

        byte[] passwordHash = md.digest();

        // print the hash
        System.out.println("Hash: "+bytesToHex(passwordHash));
        return passwordHash;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString();
    }


    public static byte[] generateSalt(int length) {
        // generate a SecureRandom instance
        SecureRandom sr = new SecureRandom();
        // create a byte array to hold the salt
        byte[] salt = new byte[length];
        // generate a random salt
        sr.nextBytes(salt);
        // print the salt
        System.out.println("Salt: " + bytesToHex(salt));
        return salt;
    }

    public static void main(String... args) throws NoSuchAlgorithmException {
        StoredPassword sp = storePassword("mysecret");

        String userPassword = args[0];
        boolean result = verify(userPassword, sp);
        System.out.println("Password verification result: " + result);
    }

    public static boolean verify(String password, StoredPassword sp) throws NoSuchAlgorithmException {
        byte[] userPasswordHash = hashPassword(password, sp.getSalt());
        return Arrays.equals(userPasswordHash, sp.getPwHash());
    }
}
