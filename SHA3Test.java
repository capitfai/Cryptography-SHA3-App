import java.math.BigInteger;
import java.util.Arrays;

public class SHA3Test {

    public static void main(String[] args) {
        SHA3Test tester = new SHA3Test();

        tester.testLeftEncode();
        tester.testLeftEncode1();
        tester.testLeftEncodeOutOfRange();
        tester.testRightEncodeOutOfRange();
        tester.testLeftEncodeZero();
        tester.testRightEncodeZero();
        tester.testEncodeString_EmptyArray();
        //tester.testEncodeString_NonEmptyArray();
        tester.testBytepad();
        cSHAKE256_test_Sample3();
    }

    public void testLeftEncode() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(12345);
        byte[] expected = {(byte) 0x02, (byte) 0x30, (byte) 0x39};
        byte[] result = sha3Instance.left_encode(x);
        assertArrayEquals(expected, result);
    }

    public void testLeftEncode1() {
        // Test input value of 1
        BigInteger input = BigInteger.ONE;
        byte[] expectedOutput = {1, 1}; // Expected output for input value of 1
        byte[] actualOutput = sha3.left_encode(input);
        assertArrayEquals(expectedOutput, actualOutput);

        // Add more test cases here if needed
    }

    public void testLeftEncodeOutOfRange() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(2).pow(2040);
        try {
            sha3Instance.left_encode(x);
            System.out.println("Test failed: Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            System.out.println("Test passed: " + e.getMessage());
        }
    }

    public void testRightEncodeOutOfRange() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(2).pow(2040);
        try {
            sha3Instance.right_encode(x);
            System.out.println(" testRightEncodeOutOfRange failed: Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            System.out.println(" testRightEncodeOutOfRange passed: " + e.getMessage());
        }
    }

    public void testLeftEncodeZero() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.ZERO;
        byte[] expected = {(byte) 0x01, (byte) 0x00};
        byte[] result = sha3Instance.left_encode(x);
        assertArrayEquals(expected, result);
    }

    public void testRightEncodeZero() {
       sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.ZERO;
        byte[] expected = {(byte) 0x00, (byte) 0x01};
        byte[] result = sha3Instance.right_encode(x);
        assertArrayEquals(expected, result);
    }

    public void testEncodeString_EmptyArray() {
        sha3 sha3Instance = new sha3();
        byte[] input = new byte[0];
        byte[] expected = {(byte) 0x01, (byte) 0x00}; // Expected output for empty input
        byte[] result = sha3Instance.encode_string(input);
        assertArrayEquals(expected, result);
    }

//    public void testEncodeString_NonEmptyArray() {
//        sha3 sha3Instance = new sha3();
//        byte[] input = "abcdefgh".getBytes(); // Input string with length 8 (multiple of 8)
//        byte[] expected = {(byte) 0x01, (byte) 0x08, 97, 98, 99, 100, 101, 102, 103, 104}; // Expected output for input "abcdefgh"
//        byte[] result = sha3Instance.encode_string(input);
//        assertArrayEquals(expected, result);
//    }

    public void testBytepad() {
        sha3 sha3Instance = new sha3();

        byte[] input = {1, 2, 3};
        int w = 4;
        byte[] expected = {
                // left_encode(4)
                0x01, 0x04,
                // input
                0x01, 0x02, 0x03,
                // padding
                0x00, 0x00, 0x00
        };
        byte[] result = sha3Instance.bytepad(input, w);
        assertArrayEquals(expected, result);
    }

    private void assertArrayEquals(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Arrays not equal");
        }
    }
    public static void testKmacxof256() {
        byte[] K = "key".getBytes();
        byte[] X = "input".getBytes();
        int L = 256; // Requested output length in bits
        byte[] S = "customization".getBytes();

        byte[] hash = sha3.KMACXOF256(K, X, L, S);
        System.out.println("KMACXOF256 Test:");
        System.out.println(Arrays.toString(hash));
    }
    public static void cSHAKE256_test_Sample3() {
        // cSHAKE sample #3
        // Strength 256-bits
        // length of data is 32 bits.
        // data is 00 01 02 03
        // requested output len is 512 bits
        // N is ""
        // S is "Email Signature"


        String N = new String("");
        var S = "Email Signature".getBytes();
        byte[] X = new byte[]{0x00, 0x01, 0x02, 0x03};

        var L = 512; // # of requested bits output.

        byte[] hash = sha3.cSHAKE256(X, L, N, S);
        var exp_text = "D0 08 82 8E 2B 80 AC 9D 22 18 FF EE 1D 07 0C 48 " +
                "B8 E4 C8 7B FF 32 C9 69 9D 5B 68 96 EE E0 ED D1 " +
                "64 02 0E 2B E0 56 08 58 D9 C0 0C 03 7E 34 A9 69 " +
                "37 C5 61 A7 4C 41 2B B4 C7 46 46 95 27 28 1C 8C ";
        System.out.println("CSHAKE256 Test:");
        phex(hash);
        // translate the output into a string. compare with expected text.
        //Sha3.phex(out);
        // return Sha3.bytesToHex(out).equals(exp_text);
    }
    public static void phex(byte[] Xs) {
        // prints a byte array
        for (var x : Xs) System.out.printf("%02X ", x);
        System.out.println();
    }
}
