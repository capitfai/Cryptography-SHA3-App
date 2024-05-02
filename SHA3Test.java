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
        tester.testBytepad();
        cSHAKE256_test_Sample3();
        cSHAKE256_test_Sample4();
        kmac256_test_Sample4();
        kmac256_test_Sample5();
    }

    public void testLeftEncode() {
        sha3 sha3Instance = new sha3();
        BigInteger leftEncodeValue = BigInteger.valueOf(12345);
        byte[] expectedLeftEncode = {(byte) 0x02, (byte) 0x30, (byte) 0x39};
        byte[] resultLeftEncode = sha3Instance.left_encode(leftEncodeValue);
        printTestResult("testLeftEncode", expectedLeftEncode, resultLeftEncode);
    }

    public void testLeftEncode1() {
        // Test input value of 1
        BigInteger inputLeftEncode1 = BigInteger.ONE;
        byte[] expectedOutputLeftEncode1 = {1, 1}; // Expected output for input value of 1
        byte[] actualOutputLeftEncode1 = sha3.left_encode(inputLeftEncode1);
        printTestResult("testLeftEncode1", expectedOutputLeftEncode1, actualOutputLeftEncode1);
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
        BigInteger leftEncodeZeroValue = BigInteger.ZERO;
        byte[] expectedLeftEncodeZero = {(byte) 0x01, (byte) 0x00};
        byte[] resultLeftEncodeZero = sha3Instance.left_encode(leftEncodeZeroValue);
        printTestResult("testLeftEncodeZero", expectedLeftEncodeZero, resultLeftEncodeZero);
    }

    public void testRightEncodeZero() {
        sha3 sha3Instance = new sha3();
        BigInteger rightEncodeZeroValue = BigInteger.ZERO;
        byte[] expectedRightEncodeZero = {(byte) 0x00, (byte) 0x01};
        byte[] resultRightEncodeZero = sha3Instance.right_encode(rightEncodeZeroValue);
        printTestResult("testRightEncodeZero", expectedRightEncodeZero, resultRightEncodeZero);
    }

    public void testEncodeString_EmptyArray() {
        sha3 sha3Instance = new sha3();

        byte[] expectedEncodeStringEmptyArray = {(byte) 0x01, (byte) 0x00}; // Expected output for empty input
        byte[] resultEncodeStringEmptyArray = sha3Instance.encode_string("");
        printTestResult("testEncodeString_EmptyArray", expectedEncodeStringEmptyArray, resultEncodeStringEmptyArray);
    }

    public void testBytepad() {
        sha3 sha3Instance = new sha3();

        byte[] inputBytepad = {1, 2, 3};
        int wBytepad = 4;
        byte[] expectedBytepad = {
                // left_encode(4)
                0x01, 0x04,
                // input
                0x01, 0x02, 0x03,
                // padding
                0x00, 0x00, 0x00
        };
        byte[] resultBytepad = sha3Instance.bytepad(inputBytepad, wBytepad);
        printTestResult("testBytepad", expectedBytepad, resultBytepad);
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
        String S = "Email Signature";
        byte[] X = new byte[]{0x00, 0x01, 0x02, 0x03};

        int L = 512; // # of requested bits output.

        byte[] hash = sha3.cSHAKE256(X, L, N, S);
        String expectedText3 = "D0 08 82 8E 2B 80 AC 9D 22 18 FF EE 1D 07 0C 48 " +
                "B8 E4 C8 7B FF 32 C9 69 9D 5B 68 96 EE E0 ED D1 " +
                "64 02 0E 2B E0 56 08 58 D9 C0 0C 03 7E 34 A9 69 " +
                "37 C5 61 A7 4C 41 2B B4 C7 46 46 95 27 28 1C 8C";
        printTestResult("cSHAKE256_test_Sample3", expectedText3, hash);
    }

    // Define the input text as a single string without any spaces
    // This string represents hexadecimal values concatenated together without spaces
    public static void cSHAKE256_test_Sample4() {
        // Strength 256-bits
        // length of data is 1600 bits.
        // data is the input text.
        // requested output len is 512 bits

        String N = new String("");
        String S = "Email Signature";
        byte[] X = new byte[200];
//        String inputText = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
//                "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F" +
//                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F" +
//                "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" +
//                "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" +
//                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
//                "C0C1C2C3C4C5C6C7";
        String inputText = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n" +
                "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F" +
                "20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F" +
                "30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F" +
                "40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F" +
                "50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F" +
                "60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F" +
                "70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F" +
                "80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F" +
                "90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F" +
                "A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF" +
                "B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF" +
                "C0 C1 C2 C3 C4 C5 C6 C7";
        String removedWhiteSpace = removeSpaces(inputText);
        String expectedText4 = "07 DC 27 B1 1E 51 FB AC 75 BC 7B 3C 1D 98 3E 8B " +
                "4B 85 FB 1D EF AF 21 89 12 AC 86 43 02 73 09 17 " +
                "27 F4 2B 17 ED 1D F6 3E 8E C1 18 F0 4B 23 63 3C " +
                "1D FB 15 74 C8 FB 55 CB 45 DA 8E 25 AF B0 92 BB";

        int L = 512; // # of requested bits output.
        testReadHex(X,  removedWhiteSpace , 200); // Convert hexadecimal string to byte array
        byte[] hash = sha3.cSHAKE256(X, L, N, S);
        printTestResult("cSHAKE256_test_Sample4", expectedText4, hash);
    }

public static void kmac256_test_Sample4() {
    // KMACXOF256 sample #4
    // Security Strength: 256-bits
    // Length of Key is 256-bits
//    String KHex = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
//    byte[] K = new byte[32];
//    testReadHex(K, KHex, 32);
    byte[] K = {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
        };

    byte[] X = new byte[]{0x00, 0x01, 0x02, 0x03};
    byte [] S = "My Tagged Application".getBytes();

    int L = 512; // # of requested bits output.

    // Expected Output
    String expectedTextKMACXOF256Sample4 = "20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64 " +
            "C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7 " +
            "F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95 " +
            "1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD";


    // Calculate KMACXOF256
    byte[] hash =  sha3.KMAC256(K, X, L, S);

    // Print results
    printTestResult("kmacxof256_test_Sample4", expectedTextKMACXOF256Sample4, hash);
}

    public static void kmac256_test_Sample5() {
        // KMACXOF256 sample #5
        // Security Strength: 256-bits
        // Length of Key is 256-bits
//    String KHex = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
//    byte[] K = new byte[32];
//    testReadHex(K, KHex, 32);
        byte[] K = {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
        };

        byte[] X = new byte[]{(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F,
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F,
                (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
                (byte)0x28, (byte)0x29, (byte)0x2A, (byte)0x2B, (byte)0x2C, (byte)0x2D, (byte)0x2E, (byte)0x2F,
                (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                (byte)0x38, (byte)0x39, (byte)0x3A, (byte)0x3B, (byte)0x3C, (byte)0x3D, (byte)0x3E, (byte)0x3F,
                (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
                (byte)0x48, (byte)0x49, (byte)0x4A, (byte)0x4B, (byte)0x4C, (byte)0x4D, (byte)0x4E, (byte)0x4F,
                (byte)0x50, (byte)0x51, (byte)0x52, (byte)0x53, (byte)0x54, (byte)0x55, (byte)0x56, (byte)0x57,
                (byte)0x58, (byte)0x59, (byte)0x5A, (byte)0x5B, (byte)0x5C, (byte)0x5D, (byte)0x5E, (byte)0x5F,
                (byte)0x60, (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
                (byte)0x68, (byte)0x69, (byte)0x6A, (byte)0x6B, (byte)0x6C, (byte)0x6D, (byte)0x6E, (byte)0x6F,
                (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74, (byte)0x75, (byte)0x76, (byte)0x77,
                (byte)0x78, (byte)0x79, (byte)0x7A, (byte)0x7B, (byte)0x7C, (byte)0x7D, (byte)0x7E, (byte)0x7F,
                (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
                (byte)0x88, (byte)0x89, (byte)0x8A, (byte)0x8B, (byte)0x8C, (byte)0x8D, (byte)0x8E, (byte)0x8F,
                (byte)0x90, (byte)0x91, (byte)0x92, (byte)0x93, (byte)0x94, (byte)0x95, (byte)0x96, (byte)0x97,
                (byte)0x98, (byte)0x99, (byte)0x9A, (byte)0x9B, (byte)0x9C, (byte)0x9D, (byte)0x9E, (byte)0x9F,
                (byte)0xA0, (byte)0xA1, (byte)0xA2, (byte)0xA3, (byte)0xA4, (byte)0xA5, (byte)0xA6, (byte)0xA7,
                (byte)0xA8, (byte)0xA9, (byte)0xAA, (byte)0xAB, (byte)0xAC, (byte)0xAD, (byte)0xAE, (byte)0xAF,
                (byte)0xB0, (byte)0xB1, (byte)0xB2, (byte)0xB3, (byte)0xB4, (byte)0xB5, (byte)0xB6, (byte)0xB7,
                (byte)0xB8, (byte)0xB9, (byte)0xBA, (byte)0xBB, (byte)0xBC, (byte)0xBD, (byte)0xBE, (byte)0xBF,
                (byte)0xC0, (byte)0xC1, (byte)0xC2, (byte)0xC3, (byte)0xC4, (byte)0xC5, (byte)0xC6, (byte)0xC7
        };
        byte [] S = "".getBytes();

        int L = 512; // # of requested bits output.

        // Expected Output
        String expectedTextKMACXOF256Sample5 = "75 35 8C F3 9E 41 49 4E 94 97 07 92 7C EE 0A F2 " +
                "0A 3F F5 53 90 4C 86 B0 8F 21 CC 41 4B CF D6 91 " +
                "58 9D 27 CF 5E 15 36 9C BB FF 8B 9A 4C 2E B1 78 " +
                "00 85 5D 02 35 FF 63 5D A8 25 33 EC 6B 75 9B 69";


        // Calculate KMACXOF256
        byte[] hash =  sha3.KMAC256(K, X, L, S);

        // Print results
        printTestResult("kmacxof256_test_Sample5", expectedTextKMACXOF256Sample5, hash);
    }




    /**
     * Convert a hexadecimal character to its corresponding integer value.
     * @param ch The hexadecimal character to convert.
     * @return The integer value corresponding to the hexadecimal character.
     *         Returns -1 if the input character is not a valid hexadecimal digit.
     */
    public static int test_hexdigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0'; // Convert character '0' - '9' to integer 0 - 9
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10; // Convert character 'A' - 'F' to integer 10 - 15
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10; // Convert character 'a' - 'f' to integer 10 - 15
        return -1; // Return -1 for non-hexadecimal characters
    }

    /**
     * Read a hexadecimal string and convert it into a byte array.
     * @param buf The byte array to store the result.
     * @param str The input hexadecimal string.
     * @param maxbytes The maximum number of bytes to read from the input string.
     * @return The number of bytes read and stored in the byte array.
     *         Returns -1 if the input string contains invalid hexadecimal characters.
     */
    public static int testReadHex(byte[] buf, String str, int maxbytes) {
        int i, h, l;
        for (i = 0; i < str.length() / 2; i++) {
            h = test_hexdigit(str.charAt(2 * i)); // Convert first hexadecimal character to integer
            if (h < 0)
                return i; // Return the index of the first invalid character
            l = test_hexdigit(str.charAt(2 * i + 1)); // Convert second hexadecimal character to integer
            if (l < 0)
                return i; // Return the index of the first invalid character
            buf[i] = (byte) ((h << 4) + l); // Combine the two integers into a byte value and store in the byte array
        }
        return i; // Return the number of bytes read and stored in the byte array
    }

    public static void printTestResult(String testName, byte[] expected, byte[] actual) {
        if (Arrays.equals(expected, actual)) {
            System.out.println(testName + " passed");
        } else {
            System.out.println(testName + " failed");
            System.out.println("Expected: " + byteArrayToHex(expected));
            System.out.println("Actual: " + byteArrayToHex(actual));
        }
    }

    public static void printTestResult(String testName, String expected, byte[] actual) {
        String actualHex = byteArrayToHex(actual);
        if (expected.equalsIgnoreCase(actualHex)) {
            System.out.println(testName + " passed");
        } else {
            System.out.println(testName + " failed");
            System.out.println("Expected: " + expected);
            System.out.println("Actual: " + actualHex);
        }
    }

    public static String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
            sb.append(" ");
        }
        return sb.toString().trim();
    }
    public static String removeSpaces(String hexWithSpaces) {

       return hexWithSpaces.replaceAll("\\s", "");
    }
}
