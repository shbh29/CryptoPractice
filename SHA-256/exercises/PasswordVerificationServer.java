import com.sun.net.httpserver.*;
import java.net.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.io.*;

public class PasswordVerificationServer extends PasswordVerification {

    private static String getLogicHTML() throws java.io.IOException {
        byte[] htmlBytes = Files.readAllBytes(Paths.get("login.html"));
        return new String(htmlBytes, StandardCharsets.UTF_8);
    }

    public static HttpServer createServerWithContext(final StoredPassword storedPassword) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);

        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String html = getLogicHTML();
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, html.length());
                OutputStream os = exchange.getResponseBody();
                os.write(html.getBytes());
                os.close();
            }
        });

        server.createContext("/verify", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("POST".equals(exchange.getRequestMethod())) {
                    InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                    BufferedReader br = new BufferedReader(isr);
                    String query = br.readLine();

                    String password = "";
                    if (query != null && query.startsWith("password=")) {
                        password = java.net.URLDecoder.decode(query.substring(9), "UTF-8");
                    }

                    boolean isValid = verify(password, storedPassword);

                    String response = "{\"valid\": " + isValid + ",\"message\": \"" + (isValid ? "Password is correct!" : "Password is incorrect!") + "\"}";

                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            }
        });

        return server;
    }

    public static void main(String[] args) throws java.io.IOException {
        final StoredPassword storedPassword = storePassword("mysecret");
        System.out.println("registered user with password 'mysecret'");
        System.out.println(storedPassword);

        HttpServer server = createServerWithContext(storedPassword);
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
        System.out.println("Try password 'mysecret' or anything else");
    }
}
