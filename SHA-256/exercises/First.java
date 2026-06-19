import java.security.*;
import java.nio.file.*;

public class First {
    public static void main(String... args) throws java.security.NoSuchAlgorithmException, java.io.IOException {
        MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");

        byte[] content = Files.readAllBytes(Paths.get("cert.cer"));
        byte[] hash = md.digest(content);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                sb.append("0");
            }
            sb.append(hex);
        }

        System.out.println("Hash: " + sb.toString().toUpperCase());
        

    }
}
