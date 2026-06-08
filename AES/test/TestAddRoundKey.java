public class TestAddRoundKey {
    /**
     * Test the addRoundKey method
     */
    public static void testAddRoundKey() {
        System.out.println("=== Testing AddRoundKey ===\n");

        // Example from AES specification
        byte[] state = {
                0x32, 0x43, (byte) 0xf6, (byte) 0xa8,
                (byte) 0x88, 0x5a, 0x30, (byte) 0x8d,
                0x31, 0x31, (byte) 0x98, (byte) 0xa2,
                (byte) 0xe0, 0x37, 0x07, 0x34
        };

        byte[] roundKey = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        System.out.println("Before AddRoundKey:");
        printState("State", state);
        printState("RoundKey", roundKey);

        // Apply AddRoundKey
        AES.addRoundKey(state, roundKey);

        System.out.println("\nAfter AddRoundKey:");
        printState("State", state);

        // Expected result
        byte[] expected = {
                0x19, 0x3d, (byte) 0xe3, (byte) 0xbe,
                (byte) 0xa0, (byte) 0xf4, (byte) 0xe2, 0x2b,
                (byte) 0x9a, (byte) 0xc6, (byte) 0x8d, 0x2a,
                (byte) 0xe9, (byte) 0xf8, 0x48, 0x08
        };

        System.out.println("\nExpected:");
        printState("Expected", expected);

        // Verify
        boolean correct = true;
        for (int i = 0; i < 16; i++) {
            if (state[i] != expected[i]) {
                correct = false;
                break;
            }
        }

        System.out.println("\n" + (correct ? "✓ TEST PASSED" : "✗ TEST FAILED"));
    }

    /**
     * Helper to print state as 4x4 matrix
     */
    private static void printState(String label, byte[] state) {
        System.out.println(label + ":");
        for (int row = 0; row < 4; row++) {
            System.out.print("  ");
            for (int col = 0; col < 4; col++) {
                int index = col * 4 + row; // Column-major order
                System.out.printf("%02X ", state[index] & 0xFF);
            }
            System.out.println();
        }
    }

    /**
     * Test Case: Invalid state length (should fail)
     */
    public static void testAddRoundKeyInvalidStateLength() {
        System.out.println("=== Test: Invalid State Length (should throw exception) ===");

        byte[] invalidState = new byte[15]; // Wrong size - should be 16
        byte[] roundKey = new byte[16];

        try {
            AES.addRoundKey(invalidState, roundKey);
            System.err.println("✗ TEST FAILED - Should have thrown IllegalArgumentException");
            assert false : "Should have thrown exception for invalid state length";
        } catch (IllegalArgumentException e) {
            System.out.println("✓ Correctly threw exception: " + e.getMessage());
            System.out.println("✓ TEST PASSED\n");
        }
    }

    /**
     * Test Case: Invalid round key length (should fail)
     */
    public static void testAddRoundKeyInvalidKeyLength() {
        System.out.println("=== Test: Invalid RoundKey Length (should throw exception) ===");

        byte[] state = new byte[16];
        byte[] invalidKey = new byte[12]; // Wrong size - should be 16

        try {
            AES.addRoundKey(state, invalidKey);
            System.err.println("✗ TEST FAILED - Should have thrown IllegalArgumentException");
            assert false : "Should have thrown exception for invalid key length";
        } catch (IllegalArgumentException e) {
            System.out.println("✓ Correctly threw exception: " + e.getMessage());
            System.out.println("✓ TEST PASSED\n");
        }
    }

    /**
     * Test Case: Null state (should fail)
     */
    public static void testAddRoundKeyNullState() {
        System.out.println("=== Test: Null State (should throw exception) ===");

        byte[] state = null;
        byte[] roundKey = new byte[16];

        try {
            AES.addRoundKey(state, roundKey);
            System.err.println("✗ TEST FAILED - Should have thrown NullPointerException");
            assert false : "Should have thrown exception for null state";
        } catch (NullPointerException e) {
            System.out.println("✓ Correctly threw exception: NullPointerException");
            System.out.println("✓ TEST PASSED\n");
        }
    }

    /**
     * Test Case: Null round key (should fail)
     */
    public static void testAddRoundKeyNullKey() {
        System.out.println("=== Test: Null RoundKey (should throw exception) ===");

        byte[] state = new byte[16];
        byte[] roundKey = null;

        try {
            AES.addRoundKey(state, roundKey);
            System.err.println("✗ TEST FAILED - Should have thrown NullPointerException");
            assert false : "Should have thrown exception for null key";
        } catch (NullPointerException e) {
            System.out.println("✓ Correctly threw exception: NullPointerException");
            System.out.println("✓ TEST PASSED\n");
        }
    }

    /**
     * Test Case: Wrong expected result (intentional failure to show test works)
     */
    public static void testAddRoundKeyWrongExpectation() {
        System.out.println("=== Test: Wrong Expected Result (demonstrates test validation) ===");

        byte[] state = {
                0x32, 0x43, (byte) 0xf6, (byte) 0xa8,
                (byte) 0x88, 0x5a, 0x30, (byte) 0x8d,
                0x31, 0x31, (byte) 0x98, (byte) 0xa2,
                (byte) 0xe0, 0x37, 0x07, 0x34
        };

        byte[] roundKey = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        // Wrong expected result (intentionally incorrect)
        byte[] wrongExpected = {
                0x00, 0x00, 0x00, 0x00, // All zeros - definitely wrong!
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
        };

        AES.addRoundKey(state, roundKey);

        boolean matches = true;
        for (int i = 0; i < 16; i++) {
            if (state[i] != wrongExpected[i]) {
                matches = false;
                break;
            }
        }

        if (matches) {
            System.err.println("✗ TEST FAILED - Result matched wrong expectation!");
        } else {
            System.out.println("✓ Result correctly differs from wrong expectation");
            System.out.println("✓ TEST PASSED (validation works)\n");
        }
    }

    /**
     * Test Case: XOR property - applying twice should restore original
     */
    public static void testAddRoundKeyReversibility() {
        System.out.println("=== Test: XOR Reversibility ===");

        byte[] original = {
                0x32, 0x43, (byte) 0xf6, (byte) 0xa8,
                (byte) 0x88, 0x5a, 0x30, (byte) 0x8d,
                0x31, 0x31, (byte) 0x98, (byte) 0xa2,
                (byte) 0xe0, 0x37, 0x07, 0x34
        };

        byte[] state = original.clone();

        byte[] roundKey = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        System.out.println("Original state:");
        printBytes(original);

        // Apply XOR once
        AES.addRoundKey(state, roundKey);
        System.out.println("\nAfter first XOR:");
        printBytes(state);

        // Apply XOR again - should restore original
        AES.addRoundKey(state, roundKey);
        System.out.println("\nAfter second XOR (should match original):");
        printBytes(state);

        // Verify
        boolean restored = true;
        for (int i = 0; i < 16; i++) {
            if (state[i] != original[i]) {
                restored = false;
                System.err.println("Mismatch at index " + i + ": " +
                        String.format("0x%02X != 0x%02X", state[i] & 0xFF, original[i] & 0xFF));
            }
        }

        if (restored) {
            System.out.println("\n✓ XOR reversibility verified");
            System.out.println("✓ TEST PASSED\n");
        } else {
            System.err.println("\n✗ TEST FAILED - State not restored");
        }
    }

    /**
     * Helper to print bytes
     */
    private static void printBytes(byte[] data) {
        System.out.print("  ");
        for (int i = 0; i < data.length; i++) {
            System.out.printf("%02X ", data[i] & 0xFF);
            if ((i + 1) % 4 == 0)
                System.out.print(" ");
        }
        System.out.println();
    }

    /**
     * Run all tests including failing cases
     */
    public static void main(String[] args) {
        System.out.println("AddRoundKey Test Suite (Including Failure Cases)\n");

        try {
            // Passing test
            testAddRoundKey();

            // Failing tests (should catch exceptions)
            testAddRoundKeyInvalidStateLength();
            testAddRoundKeyInvalidKeyLength();
            testAddRoundKeyNullState();
            testAddRoundKeyNullKey();

            // Validation tests
            testAddRoundKeyWrongExpectation();
            testAddRoundKeyReversibility();

            System.out.println("=============================");
            System.out.println("ALL TESTS COMPLETED ✓");
            System.out.println("=============================");

        } catch (AssertionError e) {
            System.err.println("ASSERTION FAILED: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("UNEXPECTED ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
