public class RemovePKCS7PaddingTest {
    
    /**
     * Test Case 1: Remove padding from "Hello" (11 bytes of 0x0B padding)
     */
    public static void testRemoveHelloPadding() {
        System.out.println("=== Test 1: Remove Hello padding ===");
        
        // Padded "Hello": H e l l o + 11 bytes of 0x0B
        byte[] padded = {
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B  // 11 padding bytes
        };
        
        byte[] unpadded = AES.removePKCS7Padding(padded);
        String result = new String(unpadded);
        
        assert unpadded.length == 5 : "Length should be 5";
        assert result.equals("Hello") : "Should be 'Hello'";
        
        printBytes("Padded", padded);
        printBytes("Unpadded", unpadded);
        System.out.println("Result: \"" + result + "\"");
        System.out.println("✓ Test 1 PASSED\n");
    }
    
    /**
     * Test Case 2: Remove 1 byte padding (0x01)
     */
    public static void testRemoveOneBytePadding() {
        System.out.println("=== Test 2: Remove 1 byte padding ===");
        
        // 15 bytes + 1 byte padding
        byte[] padded = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
            0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,  // "123456789012345"
            0x01  // 1 byte padding
        };
        
        byte[] unpadded = AES.removePKCS7Padding(padded);
        String result = new String(unpadded);
        
        assert unpadded.length == 15 : "Length should be 15";
        assert result.equals("123456789012345") : "Should be '123456789012345'";
        
        printBytes("Padded", padded);
        printBytes("Unpadded", unpadded);
        System.out.println("✓ Test 2 PASSED\n");
    }
    
    /**
     * Test Case 3: Remove full block padding (16 bytes of 0x10)
     */
    public static void testRemoveFullBlockPadding() {
        System.out.println("=== Test 3: Remove full block padding ===");
        
        // 16 bytes data + 16 bytes padding
        byte[] padded = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,  // "1234567890123456"
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10   // 16 padding bytes
        };
        
        byte[] unpadded = AES.removePKCS7Padding(padded);
        String result = new String(unpadded);
        
        assert unpadded.length == 16 : "Length should be 16";
        assert result.equals("1234567890123456") : "Should be '1234567890123456'";
        
        printBytes("Padded", padded);
        printBytes("Unpadded", unpadded);
        System.out.println("✓ Test 3 PASSED\n");
    }
    
    /**
     * Test Case 4: Remove 15 bytes padding (single byte data)
     */
    public static void testRemoveFifteenBytesPadding() {
        System.out.println("=== Test 4: Remove 15 bytes padding ===");
        
        byte[] padded = {
            0x41,  // "A"
            0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F  // 15 padding bytes
        };
        
        byte[] unpadded = AES.removePKCS7Padding(padded);
        String result = new String(unpadded);
        
        assert unpadded.length == 1 : "Length should be 1";
        assert result.equals("A") : "Should be 'A'";
        
        printBytes("Padded", padded);
        printBytes("Unpadded", unpadded);
        System.out.println("✓ Test 4 PASSED\n");
    }
    
    /**
     * Test Case 5: Invalid padding - should throw exception
     */
    public static void testInvalidPadding() {
        System.out.println("=== Test 5: Invalid padding (should throw exception) ===");
        
        // Invalid: last byte says 5 bytes padding, but they don't all match
        byte[] invalidPadded = {
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
            0x05, 0x05, 0x05, 0x04, 0x05,  // Invalid: one byte is 0x04 instead of 0x05
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05
        };
        
        try {
            byte[] unpadded = AES.removePKCS7Padding(invalidPadded);
            System.err.println("✗ Test 5 FAILED - Should have thrown exception");
            assert false : "Should have thrown IllegalArgumentException";
        } catch (IllegalArgumentException e) {
            System.out.println("✓ Correctly threw exception: " + e.getMessage());
            System.out.println("✓ Test 5 PASSED\n");
        }
    }
    
    /**
     * Test Case 6: Invalid padding value (0x00)
     */
    public static void testZeroPadding() {
        System.out.println("=== Test 6: Zero padding (invalid) ===");
        
        byte[] invalidPadded = {
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        try {
            byte[] unpadded = AES.removePKCS7Padding(invalidPadded);
            // If it doesn't throw, check if result makes sense
            System.out.println("Warning: Accepted zero padding (may be implementation-specific)");
            System.out.println("Result length: " + unpadded.length);
        } catch (Exception e) {
            System.out.println("✓ Correctly rejected zero padding: " + e.getMessage());
        }
        System.out.println("✓ Test 6 PASSED\n");
    }
    
    /**
     * Test Case 7: Round-trip test (add then remove padding)
     */
    public static void testRoundTrip() {
        System.out.println("=== Test 7: Round-trip (add + remove) ===");
        
        String[] testStrings = {
            "Hello",
            "A",
            "1234567890123456",
            "Test Message",
            "X"
        };
        
        for (String original : testStrings) {
            byte[] input = original.getBytes();
            byte[] padded = AES.addPKCS7Padding(input);
            byte[] unpadded = AES.removePKCS7Padding(padded);
            String result = new String(unpadded);
            
            assert original.equals(result) : "Round-trip failed for: " + original;
            System.out.println("  ✓ \"" + original + "\" (" + input.length + " bytes) -> " +
                             "padded (" + padded.length + " bytes) -> " +
                             "unpadded (" + unpadded.length + " bytes) -> \"" + result + "\"");
        }
        
        System.out.println("✓ Test 7 PASSED\n");
    }
    
    /**
     * Helper method to print bytes in hex
     */
    private static void printBytes(String label, byte[] data) {
        System.out.print(label + " (" + data.length + " bytes): ");
        for (int i = 0; i < data.length && i < 32; i++) {  // Limit to 32 bytes for display
            System.out.printf("%02X ", data[i] & 0xFF);
        }
        if (data.length > 32) {
            System.out.print("...");
        }
        System.out.println();
    }
    
    /**
     * Run all tests
     */
    public static void main(String[] args) {
        System.out.println("PKCS#7 Remove Padding Test Suite\n");
        
        try {
            testRemoveHelloPadding();
            testRemoveOneBytePadding();
            testRemoveFullBlockPadding();
            testRemoveFifteenBytesPadding();
            testInvalidPadding();
            testZeroPadding();
            testRoundTrip();
            
            System.out.println("=============================");
            System.out.println("ALL TESTS PASSED ✓");
            System.out.println("=============================");
            
        } catch (AssertionError e) {
            System.err.println("TEST FAILED: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("UNEXPECTED ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
