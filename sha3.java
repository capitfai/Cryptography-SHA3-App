/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;


/**
 * Part 1: Our implementation pulls inspiration from:
 * Markku-Juhani O. Saarinen
 * <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 */
public class sha3 {


    /**
     * Converts a long value to an array of bytes.
     *
     * @param l the long value to be converted
     * @return an array of bytes representing the long value
     */
    private static byte[] longToBytes(long l) {
        // Create a byte array to store the result
        byte[] result = new byte[8];

        // Iterate over each byte in the array
        for (int i = 7; i >= 0; i--) {
            // Extract the least significant byte of the long value
            // and store it in the current position of the byte array
            result[i] = (byte)(l & 0xFF);

            // Shift the bits of the long value to the right by 8 positions
            // to prepare for extracting the next byte
            l >>= 8;
        }

        // Return the byte array representing the long value
        return result;
    }
    private final static int KECCAKF_ROUNDS = 24;
    private final static boolean LITTLE_ENDIAN = true;
    // constants
    private final static long[] KECCAKF_RNDC = { 0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL,
            0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L,
            0x8000000080008008L };

    private final static int[] KECCAKF_ROTC = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61,
            20, 44 };
    private static final int[] KECCAKF_PILN = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6,
            1 };

    public static class sha3_ctx_t {

        byte[] b = new byte[200];

        int pt, rsiz, mdlen;
    };
    public static long ROTL64(long x, int y) {
        return (x << y) | (x >>> (64 - (y)));
    }

    public static void sha3_keccakf(byte[] st) {
        long[] bytes = new long[25];
        int index = 0;
        for (int i = 0; i < bytes.length; i++) {
            long value = 0;
            for (int j = 0; j < 8; j++) {
                value <<= 8; // Shift the value to the left by 8 bits
                value |= (st[index++] & 0xFF); // Extract the byte and append it to the value
            }
            bytes[i] = value; // Assign the constructed long value to the array
        }

        // variables
        int i, j, r;
        long t;
        long[] bc = new long[5];

        if (LITTLE_ENDIAN) {
            byte[] v;
            for (i = 0; i < 25; i++) {
                v = longToBytes(bytes[i]);
                bytes[i] = (((long) v[0]) & 0xFF) | ((((long) v[1]) & 0xFF) << 8) | ((((long) v[2]) & 0xFF) << 16)
                        | ((((long) v[3]) & 0xFF) << 24) | ((((long) v[4]) & 0xFF) << 32)
                        | ((((long) v[5]) & 0xFF) << 40) | ((((long) v[6]) & 0xFF) << 48)
                        | ((((long) v[7]) & 0xFF) << 56);
            }
        }

        // actual iteration
        for (r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (i = 0; i < 5; i++)
                bc[i] = bytes[i] ^ bytes[i + 5] ^ bytes[i + 10] ^ bytes[i + 15] ^ bytes[i + 20];

            for (i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5)
                    bytes[j + i] ^= t;
            }

            // Rho Pi
            t = bytes[1];
            for (i = 0; i < 24; i++) {
                j = KECCAKF_PILN[i];
                bc[0] = bytes[j];
                bytes[j] = ROTL64(t, KECCAKF_ROTC[i]);
                t = bc[0];
            }

            // Chi
            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++)
                    bc[i] = bytes[j + i];
                for (i = 0; i < 5; i++)
                    bytes[j + i] ^= ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
            }

            // Iota
            bytes[0] ^= KECCAKF_RNDC[r];
        }

        if (LITTLE_ENDIAN) {
            byte[] v;
            for (i = 0; i < 25; i++) {
                v = longToBytes(bytes[i]);
                bytes[i] = (((long) v[0]) & 0xFF) | ((((long) v[1]) & 0xFF) << 8) | ((((long) v[2]) & 0xFF) << 16)
                        | ((((long) v[3]) & 0xFF) << 24) | ((((long) v[4]) & 0xFF) << 32)
                        | ((((long) v[5]) & 0xFF) << 40) | ((((long) v[6]) & 0xFF) << 48)
                        | ((((long) v[7]) & 0xFF) << 56);
            }
        }

        int counter = 0;
        for (int b = 0; b < bytes.length; b++) {
            byte[] newArr = longToBytes(bytes[b]);
            for (int c = 0; c < 8; c++) {
                st[counter++] = newArr[c];
            }
        }
    }

    private static void sha3_init(sha3_ctx_t c, int mdlen) {
        for (int i = 0; i < 200; i++)
            c.b[i] = 0;
        c.mdlen = mdlen;
        c.rsiz = 200 - 2 * mdlen;
        c.pt = 0;
    }

    private static void sha3_update(sha3_ctx_t c, byte[] data, int len) {
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            c.b[j++] ^= data[i];
            if (j >= c.rsiz) {
                sha3_keccakf(c.b);
                j = 0;
            }
        }
        c.pt = j;
    }

    /**
     *
     * This method prepares the SHA-3 hash context for generating additional output using the extensible-output feature.
     * For cSHAKE, it XORs the byte at the current position with the provided xorValue (0x04 for cShake, 0x1F for Shake),
     * XORs the byte at the end of the byte array with 0x80 to mark the end of input,
     * performs the Keccak-f permutation on the state represented by stWords array,
     * and resets the position pointer to 0 for subsequent operations.
     *
     * @param c   The context containing the internal state.
     * @param xorValue The XOR value used for customization. For cSHAKE, it's 0x04 for cShake, and 0x1F for Shake.
     */
    private static void shake_xof(sha3_ctx_t c,byte xorValue ) {
        c.b[c.pt] ^= xorValue;
        c.b[c.rsiz - 1] ^= 0x80;
        sha3_keccakf(c.b);
        c.pt = 0;
    }

    /**
     * Reads bytes from the internal state of a SHA-3 context and stores them in the output array.
     * If the output length exceeds the internal buffer size, the SHA-3 permutation function is applied
     * to update the internal state before continuing to read bytes.
     *
     * @param c   The SHA-3 context from which bytes are read.
     * @param out The array to store the output bytes.
     * @param len The number of bytes to read and store in the output array.
     */
    private static void shake_out(sha3_ctx_t c, byte[] out, int len) {
        int i;
        int j = c.pt;
        for (i = 0; i < len; i++) {
            // If the current position in the internal buffer exceeds its size,
            // apply the SHA-3 permutation function to update the internal state
            if (j >= c.rsiz) {
                sha3_keccakf(c.b);
                j = 0;
            }
            // Copy the byte from the internal buffer to the output array
            out[i] = c.b[j++];
        }

        // Update the position pointer in the SHA-3 context
        c.pt = j;
    }

    /**
     * Computes KMACXOF256 (KMAC eXtendable-Output Function) as specified in the NIST SP 800-185 standard.
     *
     * @param K     The key bit string of any length, including zero.
     * @param X     The main input bit string of any length, including zero.
     * @param L     The requested output length in bits.
     * @param S     An optional customization bit string of any length, including zero.
     *              If no customization is desired, S should be set to an empty byte array.
     * @return      The computed KMACXOF256 output as a byte array.
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // Check validity conditions
        if (K.length >= Math.pow(2, 2040) || S.length >= Math.pow(2, 2040) || L < 0) {
            throw new IllegalArgumentException("Invalid input length or value.");
        }
        byte[] bytePaddedK = bytepad(encode_string(new String(K, StandardCharsets.UTF_8)), 136);

        // Concatenate paddedK and X into concatencodedXPadK
        byte[] concatencodedXPadK = new byte[bytePaddedK.length + X.length];
        for (int i = 0; i < bytePaddedK.length; i++) {
            concatencodedXPadK[i] = bytePaddedK[i];
        }
        for (int i = 0; i < X.length; i++) {
            concatencodedXPadK[bytePaddedK.length + i] = X[i];
        }

        // Compute right encoding of L
        byte[] encodedLeft = right_encode(BigInteger.valueOf(0));

        // Concatenate concatencodedXPadK and encodedLeft into newX
        byte[] newX = new byte[encodedLeft.length + concatencodedXPadK.length];
        for (int i = 0; i < concatencodedXPadK.length; i++) {
            newX[i] = concatencodedXPadK[i];
        }
        for (int i = 0; i < encodedLeft.length; i++) {
            newX[concatencodedXPadK.length + i] = encodedLeft[i];
        }

        String convertByteToString = new String(S);
        return cSHAKE256(newX, L, "KMAC", convertByteToString);
    }


    /**
     * Computes KMACXOF256 (KMAC eXtendable-Output Function) as specified in the NIST SP 800-185 standard.
     *
     * @param K     The key bit string of any length, including zero.
     * @param X     The main input bit string of any length, including zero.
     * @param L     The requested output length in bits.
     * @param S     An optional customization bit string of any length, including zero.
     *              If no customization is desired, S should be set to an empty byte array.
     * @return      The computed KMACXOF256 output as a byte array.
     */
    public static byte[] KMAC256(byte[] K, byte[] X, int L, byte[] S) {
        // Check validity conditions
        if (K.length >= Math.pow(2, 2040) || S.length >= Math.pow(2, 2040) || L < 0) {
            throw new IllegalArgumentException("Invalid input length or value.");
        }
        byte[] bytePaddedK= bytepad(encode_string(new String(K, StandardCharsets.UTF_8)), 136);

        // Concatenate paddedK and X into concatencodedXPadK
        byte[] concatencodedXPadK = new byte[bytePaddedK.length + X.length];
        for (int i = 0; i < bytePaddedK.length; i++) {
            concatencodedXPadK[i] = bytePaddedK[i];
        }
        for (int i = 0; i < X.length; i++) {
            concatencodedXPadK[bytePaddedK.length + i] = X[i];
        }

        // Compute right encoding of L
        byte[] encodedLeft = right_encode(BigInteger.valueOf(L));

        // Concatenate concatencodedXPadK and encodedLeft into newX
        byte[] newX = new byte[encodedLeft.length + concatencodedXPadK.length];
        for (int i = 0; i < concatencodedXPadK.length; i++) {
            newX[i] = concatencodedXPadK[i];
        }
        for (int i = 0; i < encodedLeft.length; i++) {
            newX[concatencodedXPadK.length + i] = encodedLeft[i];
        }

        String convertByteToString = new String(S);
        return cSHAKE256(newX, L, "KMAC", convertByteToString);
    }
    /**
     * Compute cSHAKE256 using the provided parameters.
     *
     * @param X Input byte array X.
     * @param L Output length in bytes.
     * @param N Customization string.
     * @param S Customization string.
     * @return cSHAKE256 output as a byte array.
     */
    public static byte[] cSHAKE256(byte[] X, int L, String N, String S) {
        if (N.length() == 0 && S.length() == 0)
            return SHAKE256(X, L);
        byte[] encodedNToBytes = encode_string(N);
        byte[] encodedSToBytes = encode_string(S);
        byte[] NS = new byte[encodedNToBytes.length + encodedSToBytes.length];
        for (int i = 0; i < encodedNToBytes.length; i++) {
            NS[i] = encodedNToBytes[i];
        }
        for (int i = 0; i < encodedSToBytes.length; i++) {
            NS[encodedNToBytes.length + i] = encodedSToBytes[i];
        }
        byte[] bytepadNS = bytepad(NS, 136);
        byte[] res = new byte[bytepadNS.length + X.length];
        for (int i = 0; i < bytepadNS.length; i++) {
            res[i] = bytepadNS[i];
        }
        for (int i = 0; i < X.length; i++) {
            res[bytepadNS.length + i] = X[i];
        }
        return sponge(res, L, (byte) 0x04);
    }
public static byte[] SHAKE256(byte[] M, int d) {
    byte[]  newArr= new byte[M.length];
    for (int i = 0; i < M.length; i++) {
        newArr[i] = M[i];
    }
    return sponge(newArr, d, (byte) 0x1F);
}

    /**
     * Perform the sponge function using the SHA-3 algorithm.
     *
     * @param data      The input data to be processed.
     * @param d         The desired output length in bits.
     *@param xorValue The XOR value used for customization. For cSHAKE, it's 0x04 for cShake, and 0x1F for Shake.
     * @return          The resulting output bytes.
     */
    private static byte[] sponge(byte[] data, int d, byte xorValue) {
        sha3_ctx_t sha3 = new sha3_ctx_t(); // Create an instance of sha3_ctx_t static class
        int outLength = d / 8; // Calculate the length of the output in bytes
        byte[] out = new byte[outLength]; // Initialize the output byte array
        sha3_init(sha3, 32); // Initialize the SHA-3 context with a hash length of 32 bytes
        absorb(sha3, data); // Absorb the input data into the SHA-3 context
        squeeze(sha3, out, xorValue, outLength); // Squeeze the output bytes from the SHA-3 context
        return out; // Return the resulting output byte array
    }

    /**
     * Absorb the input data into the SHA-3 context.
     *
     * @param sha3 The SHA-3 context to absorb the data into.
     * @param data The input data to be absorbed.
     */
    private static void absorb(sha3_ctx_t sha3, byte[] data) {
        sha3_update(sha3, data, data.length); // Update the SHA-3 context with the input data
    }
    /**
     * Squeeze the output bytes from the SHA-3 context.
     *
     * @param sha3       The SHA-3 context to squeeze the output from.
     * @param output     The byte array to store the squeezed output.
     * @param xorValue The XOR value used for customization. For cSHAKE, it's 0x04 for cShake, and 0x1F for Shake.
     * @param byteLength The length of the output in bytes.
     */
    private static void squeeze(sha3_ctx_t sha3, byte[] output, byte xorValue, int byteLength) {
        shake_xof(sha3, xorValue); // Apply the XOF operation to the SHA-3 context
        shake_out(sha3, output, byteLength); // Extract the output bytes from the SHA-3 context
    }
    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    public static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || X.
        byte[] wenc = left_encode(BigInteger.valueOf(w));
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)];
        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        // 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        // 4. return z
        return z;
    }


    /**
     * Encodes an integer as a byte string in a way that can be unambiguously parsed
     * from the end of the string by inserting the length of the byte string
     * after the byte string representation of x.
     *
     * @param x The integer to encode.
     * @return The byte array representing the encoded integer.
     * @throws IllegalArgumentException if the input value is out of range.
     */
    public static byte[] right_encode(BigInteger x) {
        if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(BigInteger.valueOf(2).pow(2040)) >= 0) {
            throw new IllegalArgumentException("Input must be within the range [0, 2^2040).");
        }
        if (x.equals(BigInteger.ZERO)) {
            return new byte[] { 0, 1 };
        }
        // Determine the number of bytes needed to represent x
        int n = (x.bitLength() + 7) / 8;

        // Create a new array with an additional byte for the length
        byte[] O = new byte[n + 1];
        byte[] xi = x.toByteArray();

        // Encode each byte of x
        int xiIndex = xi.length - 1;
        for (int i = n - 1; i >= 0; i--) {
            if (xiIndex >= 0) {
                O[i] = xi[xiIndex];
                xiIndex--;
            } else {
                O[i] = 0;
            }
        }

        // Set the last byte of O to the length (n)
        O[n] = (byte) n;

        return O;


    }

    /**
     * Encode an integer as a byte array in a way that can be parsed from the beginning of the string.
     *
     * @param x The integer to encode.
     * @return The byte array representing the encoded integer.
     * @throws IllegalArgumentException if the input value is out of range.
     */
    public static byte[] left_encode(BigInteger x) {
        // Check if the input value is out of range
        if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(BigInteger.valueOf(2).pow(2040)) >= 0) {
            throw new IllegalArgumentException("Input value out of range");
        }

        // Special case for zero
        if (x.compareTo(BigInteger.ZERO) == 0) {
            // If x is zero, return a byte array with length 1 and value 0x01 0x00
            return new byte[]{1, 0};
        }

        // Determine the number of bytes needed to represent x
        int numBytes = (x.bitLength() + 7) / 8;
        // Create a byte array of appropriate size
        byte[] result = new byte[numBytes + 1];

        // Encode the length of the byte array
        result[0] = (byte) numBytes;

        // Encode the integer into the byte array in big-endian format
        int index = numBytes;
        while (x.compareTo(BigInteger.ZERO) > 0) {
            // Extract the least significant byte of x and store it in the byte array
            result[index] = x.and(BigInteger.valueOf(0xFF)).byteValue();
            // Shift x to the right by 8 bits to process the next byte
            x = x.shiftRight(8);
            // Move to the previous index in the byte array
            index--;
        }

        return result;

    }


    /**
     * Encode a bit string in a way that can be parsed unambiguously from the beginning of the string.
     *
     * @param s The input bit string as a byte array.
     * @return The encoded bit string as a byte array.
     */
    public static byte[] encode_string(String s) {

        BigInteger bitLength = BigInteger.valueOf(s.length()*8);
        byte[] lenSBytes = left_encode(bitLength); // Convert length of S to bytes (left encoded)
        byte[] SBytes = s.getBytes(StandardCharsets.UTF_8); // Get bytes of S
        byte[] result = new byte[lenSBytes.length + SBytes.length]; // Concatenate length and S

        // Manual loop for copying bytes
        for (int i = 0; i < lenSBytes.length; i++) {
            result[i] = lenSBytes[i];
        }
        for (int i = 0; i < SBytes.length; i++) {
            result[lenSBytes.length + i] = SBytes[i];
        }

        return result;
    }
}