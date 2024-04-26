import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

import java.math.BigInteger;

public class SHA3Test {

    @Test
    public void testLeftEncode() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(12345);
        byte[] expected = {(byte) 0x02, (byte) 0x30, (byte) 0x39};
        byte[] result = sha3Instance.left_encode(x);
        assertArrayEquals(expected, result);
    }
    @Test
    public void testLeftEncode1() {
        // Test input value of 1
        BigInteger input = BigInteger.ONE;
        byte[] expectedOutput = {1, 1}; // Expected output for input value of 1
        byte[] actualOutput = sha3.left_encode(input);
        assertArrayEquals(expectedOutput, actualOutput);

        // Add more test cases here if needed
    }


    @Test(expected = IllegalArgumentException.class)
    public void testLeftEncodeOutOfRange() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(2).pow(2040);
        sha3Instance.left_encode(x);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRightEncodeOutOfRange() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.valueOf(2).pow(2040);
        sha3Instance.right_encode(x);
    }

    @Test
    public void testLeftEncodeZero() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.ZERO;
        byte[] expected = {(byte) 0x01, (byte) 0x00};
        byte[] result = sha3Instance.left_encode(x);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testRightEncodeZero() {
        sha3 sha3Instance = new sha3();
        BigInteger x = BigInteger.ZERO;
        byte[] expected = {(byte) 0x00, (byte) 0x01};
        byte[] result = sha3Instance.right_encode(x);
        assertArrayEquals(expected, result);
    }
    @Test
    public void testEncodeString_EmptyArray() {
        sha3 sha3Instance = new sha3();
        byte[] input = new byte[0];
        byte[] expected = {(byte) 0x01, (byte) 0x00}; // Expected output for empty input
        byte[] result = sha3.encode_string(input);
        assertArrayEquals(expected, result);
    }
    @Test
    public void testEncodeString_NonEmptyArray() {
        sha3 sha3Instance = new sha3();
        byte[] input = "abcdefgh".getBytes(); // Input string with length 8 (multiple of 8)
        byte[] expected = {(byte) 0x01, (byte) 0x08, 97, 98, 99, 100, 101, 102, 103, 104}; // Expected output for input "abcdefgh"
        byte[] result = sha3.encode_string(input);
        assertArrayEquals(expected, result);
    }

    @Test
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
        byte[] result = sha3.bytepad(input, w);
        assertArrayEquals(expected, result);
    }
}
