
public class PKCS7PaddingTest {

    /**
     * Test Case 1: "Hello" - 5 bytes needs 11 bytes padding
     */
    public static void testHelloPadding() {
        System.out.println("=== Test 1: Hello (5 bytes) ===");

        byte[] input = "Hello".getBytes();
        byte[] padded = AES.addPKCS7Padding(input);

        // Expected: 16 bytes total, last 11 bytes should be 0x0B
        assert padded.length == 16 : "Length should be 16";

        // Check original data is preserved
        for (int i = 0; i < 5; i++) {
            assert padded[i] == input[i] : "Original data corrupted";
        }

        // Check padding bytes (should all be 0x0B = 11)
        for (int i = 5; i < 16; i++) {
            assert padded[i] == 0x0B : "Padding byte should be 0x0B";
        }

        printBytes("Input", input);
        printBytes("Padded", padded);
        System.out.println("✓ Test 1 PASSED\n");
    }

    /**
     * Test Case 2: Empty string - needs full block (16 bytes of 0x10)
     */
    public static void testEmptyString() {
        System.out.println("=== Test 2: Empty String (0 bytes) ===");

        byte[] input = "".getBytes();
        byte[] padded = AES.addPKCS7Padding(input);

        // Expected: 16 bytes, all should be 0x10
        assert padded.length == 16 : "Length should be 16";

        for (int i = 0; i < 16; i++) {
            assert padded[i] == 0x10 : "All bytes should be 0x10";
        }

        printBytes("Input", input);
        printBytes("Padded", padded);
        System.out.println("✓ Test 2 PASSED\n");
    }

    /**
     * Test Case 3: 15 bytes - needs 1 byte padding
     */
    public static void testAlmostFullBlock() {
        System.out.println("=== Test 3: 15 bytes (needs 1 byte padding) ===");

        byte[] input = "123456789012345".getBytes(); // 15 bytes
        byte[] padded = AES.addPKCS7Padding(input);

        // Expected: 16 bytes, last byte should be 0x01
        assert padded.length == 16 : "Length should be 16";
        assert padded[15] == 0x01 : "Last byte should be 0x01";

        // Check original data
        for (int i = 0; i < 15; i++) {
            assert padded[i] == input[i] : "Original data corrupted";
        }

        printBytes("Input", input);
        printBytes("Padded", padded);
        System.out.println("✓ Test 3 PASSED\n");
    }

    /**
     * Test Case 4: Exactly 16 bytes - needs full block padding
     */
    public static void testExactBlock() {
        System.out.println("=== Test 4: Exactly 16 bytes ===");

        byte[] input = "1234567890123456".getBytes(); // 16 bytes
        byte[] padded = AES.addPKCS7Padding(input);

        // Expected: 32 bytes (16 original + 16 padding)
        assert padded.length == 32 : "Length should be 32";

        // Check original data
        for (int i = 0; i < 16; i++) {
            assert padded[i] == input[i] : "Original data corrupted";
        }

        // Check padding (all 0x10)
        for (int i = 16; i < 32; i++) {
            assert padded[i] == 0x10 : "Padding should be 0x10";
        }

        printBytes("Input", input);
        printBytes("Padded", padded);
        System.out.println("✓ Test 4 PASSED\n");
    }

    /**
     * Test Case 5: 1 byte - needs 15 bytes padding
     */
    public static void testSingleByte() {
        System.out.println("=== Test 5: Single byte (needs 15 bytes padding) ===");

        byte[] input = "A".getBytes();
        byte[] padded = AES.addPKCS7Padding(input);

        // Expected: 16 bytes, last 15 should be 0x0F
        assert padded.length == 16 : "Length should be 16";
        assert padded[0] == 'A' : "First byte should be 'A'";

        for (int i = 1; i < 16; i++) {
            assert padded[i] == 0x0F : "Padding should be 0x0F";
        }

        printBytes("Input", input);
        printBytes("Padded", padded);
        System.out.println("✓ Test 5 PASSED\n");
    }

    /**
     * Test Case 6: Round-trip test (pad then unpad)
     */
    public static void testRoundTrip() {
        System.out.println("=== Test 6: Round-trip (pad + unpad) ===");

        String[] testStrings = { "Hello", "A", "", "1234567890123456", "Test" };

        for (String original : testStrings) {
            byte[] input = original.getBytes();
            byte[] padded = AES.addPKCS7Padding(input);
            byte[] unpadded = AES.removePKCS7Padding(padded);
            String result = new String(unpadded);

            assert original.equals(result) : "Round-trip failed for: " + original;
            System.out.println("  ✓ \"" + original + "\" -> pad -> unpad -> \"" + result + "\"");
        }

        System.out.println("✓ Test 6 PASSED\n");
    }

    /**
     * Test Case: Empty String Round-Trip
     * Empty string (0 bytes) should pad to full block (16 bytes of 0x10)
     * Then unpad back to empty string
     */
    public static void testEmptyStringRoundTrip() {
        System.out.println("=== Test: Empty String Round-Trip ===");

        // Step 1: Start with empty string
        String original = "";
        byte[] input = original.getBytes();
        System.out.println("Original: \"" + original + "\" (" + input.length + " bytes)");
        printBytes("Input", input);

        // Step 2: Add padding
        byte[] padded = AES.addPKCS7Padding(input);
        System.out.println("\nAfter padding:");
        printBytes("Padded", padded);

        // Verify padding is correct
        assert padded.length == 16 : "Padded length should be 16";
        for (int i = 0; i < 16; i++) {
            assert (padded[i] & 0xFF) == 0x10 : "All bytes should be 0x10 (16)";
        }
        System.out.println("✓ Padding correct: 16 bytes, all 0x10");

        // Step 3: Remove padding
        byte[] unpadded = AES.removePKCS7Padding(padded);
        String result = new String(unpadded);
        System.out.println("\nAfter removing padding:");
        printBytes("Unpadded", unpadded);
        System.out.println("Result: \"" + result + "\" (" + unpadded.length + " bytes)");

        // Step 4: Verify result
        assert unpadded.length == 0 : "Unpadded length should be 0";
        assert result.equals(original) : "Should be empty string";

        System.out.println("\n✓ Empty string round-trip successful!");
        System.out.println("  0 bytes -> 16 bytes (padded) -> 0 bytes (unpadded)");
        System.out.println("✓ Test PASSED\n");
    }

    /**
     * Helper method to print bytes in hex
     */
    private static void printBytes(String label, byte[] data) {
        System.out.print(label + " (" + data.length + " bytes): ");
        for (byte b : data) {
            System.out.printf("%02X ", b & 0xFF);
        }
        System.out.println();
    }

    /**
     * Run all tests
     */
    public static void main(String[] args) {
        System.out.println("PKCS#7 Padding Test Suite\n");

        try {
            testHelloPadding();
            testEmptyString();
            testAlmostFullBlock();
            testExactBlock();
            testSingleByte();
            testRoundTrip();
            testEmptyStringRoundTrip();

            System.out.println("=============================");
            System.out.println("ALL TESTS PASSED ✓");
            System.out.println("=============================");

        } catch (AssertionError e) {
            System.err.println("TEST FAILED: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
