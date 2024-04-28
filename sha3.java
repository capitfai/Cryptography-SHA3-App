import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of SHA-3 hashing algorithm.
 */
public class sha3 {
    // Define a nested class to represent the state context
    public static class sha3_ctx_t  {
        // Public fields to represent the state context
        public byte[] stBytes = new byte[200]; // 8-bit bytes
        public long[] stWords = new long[25];  // 64-bit words
        public int pt;
        public int rsiz;
        public int mdlen;
    }
    // Constants for Keccak-f permutation

    // Round constants used in the Iota step
    private static final long[] KECCAKF_RNDC = {
            // Round constants used in the Iota step
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    // Rotation constants used in the Rho step
    private static final int[] KECCAKF_ROTC = {
            // Rotation constants used in the Rho step
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    // Permutation indices used in the Pi step
    private static final int[] KECCAKF_PILN = {
            // Permutation indices used in the Pi step
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
    private static final int KECCAKF_ROUNDS = 24;
    // in bytes, e.g. 1600 bits
    private static final int WIDTH = 200;
    // dimension of lanes
    private static final int DM = 5;

    private long[] state = new long[25];


    /**
     * Core Keccak-f permutation function.
     *
     * This function applies the Keccak-f permutation for a fixed number of rounds.
     * It includes the Theta, Rho, Pi, Chi, and Iota steps.
     *
     * @param state The array representing the internal state of the Keccak sponge function.
     */
    public static void sha3_keccakf(long[] state) {


        long[] bc = new long[5];

        long[][] tmp = new long[5][5];


        // Endianness conversion (only for big-endian targets) - before permutation
        // This conversion ensures that the input state is in little-endian format,
        // as required by the Keccak permutation. If the native byte order is big-endian,
        // the state array elements are reversed to convert them to little-endian.
        if (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN) {
            for (int i = 0; i < 25; i++) {
                state[i] = Long.reverseBytes(state[i]);
            }
        }

        // Perform Keccak-f permutation for a fixed number of rounds
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta step: Constants used here to compute parity bits for each column

            for (int i = 0; i < 5; i++)
                bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

            // Rho and Pi steps: Constants used to rotate and permute bits within the state
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    tmp[i][j] = state[i + 5 * j];
                }
            }
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    //Long.rotateLeft efficiently rotates the bits within a 64-bit word, achieving the same effect as ROTL64
                    state[j * 5 + KECCAKF_PILN[i + 5 * j]] = Long.rotateLeft(tmp[i][j], KECCAKF_ROTC[i + 5 * j]);
                }
            }

            // Chi step: Constants used to compute new bit values based on neighboring bits
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++)
                    bc[i] = state[j + i];
                for (int i = 0; i < 5; i++)
                    state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            // Iota step: Constants used to introduce round constants into the state
            state[0] ^= KECCAKF_RNDC[r];
        }

        // Endianness conversion (only for big-endian targets) - after permutation
        if (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN) {
            for (int i = 0; i < 25; i++) {
                state[i] = Long.reverseBytes(state[i]);
            }
        }
    }




    /**
     * Initialize the context for SHA3.
     * @param c  the context
     * @param mdlen Length of the message digest in bytes.
     */
    private static void sha3_init(sha3_ctx_t c, int mdlen) {
        for (int i = 0; i < 25; i++) {
            c.stWords[i] = 0;
        }
        c.mdlen = mdlen;
        c.rsiz = 200 - 2 * mdlen;
        c.pt = 0;
    }

    /**
     * Update state with more data.
     * @param c  the context
     * @param data Input data as byte array.
     * @param len of the input data in bytes
     */
    private static void sha3_update(sha3_ctx_t c, byte[] data, int len) {
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            c.stBytes[j++] ^= data[i];
            if (j >= c.rsiz) {
                sha3_keccakf(c.stWords);
                j = 0;
            }
        }
        c.pt = j;
    }



//
//    /**
//     * Compute a SHA-3 hash of given byte length from input.
//     *
//     * @param in Input data as byte array.
//     * @return The computed hash as a byte array.
//     */
//    public byte[] sha3(byte[] in) {
//        sha3_init(mdlen);
//        sha3_update(in);
//        return sha3_final();
//    }

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
    static void shake_xof(sha3_ctx_t c, byte xorValue) {
        // XORs the byte at the current position with the provided xorValue
        c.stBytes[c.pt] ^= xorValue;

        // XORs the byte at the end of the byte array with 0x80 to mark the end of input
        c.stBytes[c.rsiz - 1] ^= 0x80;

        // Performs the Keccak-f permutation on the state represented by stWords array
        sha3_keccakf(c.stWords);

        // Resets the position pointer to 0 for subsequent operations
        c.pt = 0;
    }
    /**
     * Extracts output bytes from the SHA-3 hash context.
     * This method retrieves output bytes from the SHA-3 hash context,
     * writing them to the provided output array.
     *
     * @param c   The  context representing the state of the hash function.
     * @param out The output array where the extracted bytes will be stored.
     * @param len The number of bytes to extract from the context.
     */
    private static void shake_out(sha3_ctx_t c, byte[] out, int len) {
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            if (j >= c.rsiz) {
                sha3_keccakf(c.stWords);
                j = 0;
            }
            out[i] = c.stBytes[j++];
        }

        c.pt = j;
    }

    /**
     * Absorbs the input data into the sponge state.
     *
     * @param c  The context containing the internal state.
     * @param data The input data to be absorbed.
     */
    private static void absorb(sha3_ctx_t c, byte[] data) {
        sha3_init(c, 32); // Initialize SHA-3 context with a hash length of 256 bits
        sha3_update(c, data, data.length);
    }

    /**
     * Squeezes the sponge state to generate output bytes.
     *
     * @param c  The context containing the internal state.
     * @param len The length of the output in bytes.
     * @param xorValue The XOR value used for customization. For cSHAKE, it's 0x04 for cShake, and 0x1F for Shake.
     * @return The output bytes generated by squeezing the sponge state.
     */
    private static byte[] squeeze(sha3_ctx_t c, int len, byte xorValue ) {
        byte[] result = new byte[len];
        shake_xof(c, xorValue); // Prepare for squeezing with cSHAKE customization if flag is true
        shake_out(c, result, len);
        return result;
    }

    /**
     * Applies the sponge construction to perform hashing or extendable-output functions (XOF).
     *
     * @param data The input data to be processed.
     * @param len   The desired output length in bits.
     * @param xorValue The XOR value used for customization. For cSHAKE, it's 0x04 for cShake, and 0x1F for Shake.
     * @return The output bytes generated by the sponge function.
     */
    private static byte[] sponge(sha3_ctx_t c,byte[] data, int len, byte xorValue ) {
        int inputLen = len / 8;
        absorb(c, data); // Absorb the input data into the sponge state
        return squeeze(c, inputLen ,xorValue  ); // Squeeze the sponge state to generate output bytes
    }

    /**
     * Compute SHAKE256 hash, which is an Extendable-Output Function (XOF) based on SHA-3.
     * SHAKE256 allows generating variable-length hash outputs.
     *
     * @param X The input data as byte array.
     * @param L The desired output length in bits.
     * @return The computed SHAKE256 hash as a byte array.
     */
    public static byte[]  SHAKE256(byte[] X, int L) {

        sha3_ctx_t c = new sha3_ctx_t(); // Context for SHAKE256 function
        byte[] input = new byte[X.length]; // Create input array of same length as data
        for (int i = 0; i < X.length; i++) {
            input[i] = X[i]; // Copy data into input array
        }
        return sponge(c, input, L, (byte) 0x1F); // Use 0x1F for Shake customization
    }

    /**
     * Compute cSHAKE256 hash, which is an Extendable-Output Function (XOF) based on SHA-3
     * with additional domain separation capability provided by the function name and customization string.
     * cSHAKE256 allows generating variable-length hash outputs.
     *
     * @param X The main input bit string.
     * @param L The requested output length in bits.
     * @param N The function-name bit string.
     * @param S The customization bit string.
     * @return The computed cSHAKE256 hash as a byte array.
     */
    public static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        if (N.length == 0 && S.length == 0) {
            return  SHAKE256(X, L); // Use SHAKE256 if N and S are empty
        } else {


            byte[] storedN = encode_string(bytepad(encode_string(N), 136)); // Encoding with padding
            byte[] storedS = encode_string(S);
            int inputLen = storedN.length + storedS.length + X.length;
            byte[] input = new byte[inputLen];

            // Copy encoded function name
            int index = 0;
            for (byte b : storedN) {
                input[index++] = b;
            }

            // Copy encoded customization string
            for (byte b : storedS) {
                input[index++] = b;
            }

            // Copy input data
            for (byte b : X) {
                input[index++] = b;
            }

            sha3_ctx_t c = new sha3_ctx_t(); // Context for cSHAKE256 function
            return sponge(c, input, L, (byte) 0x04); // Use 0x04 for cShake customization
        }
    }
    /**
     * Compute KMACXOF256 hash, which is a variant of the KECCAK Message Authentication Code (KMAC)
     * algorithm based on SHA-3 with customizable output length.
     * KMACXOF256 allows generating variable-length hash outputs.
     *
     * @param K The key bit string of any length.
     * @param X The main input bit string of any length.
     * @param L The requested output length in bits.
     * @param S The optional customization bit string of any length. If no customization is desired, S should be an empty byte array.
     * @return The computed KMACXOF256 hash as a byte array.
     * @throws IllegalArgumentException if the input lengths are invalid.
     */
    public static byte[] kmacxof256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] N = new byte[]{(byte) 0b11010010, (byte) 0b10110010, (byte) 0b10000010, (byte) 0b11000010}; // Name for KMAC function
        byte[] newX;
        if (K.length < 2 || L >= Math.pow(2, 2040) || S.length >= Math.pow(2, 2040)) {
            throw new IllegalArgumentException("Invalid input length");
        }

        // Pad the key and concatenate with input and right-encoded output length
        if (K.length >= 32) {
            newX = bytepad(encode_string(K), 136); // Using 136-byte padding for KECCAK[512]
        } else {
            newX = bytepad(encode_string(K), 168); // Using 168-byte padding for KECCAK[256]
        }

        // Create a new array to store the concatenated data
        byte[] concatenatedData = new byte[newX.length + X.length + right_encode(BigInteger.valueOf(L)).length];

        // Copy the padded key into the concatenatedData array
        for (int i = 0; i < newX.length; i++) {
            concatenatedData[i] = newX[i];
        }

        // Copy the input X into the concatenatedData array
        for (int i = 0; i < X.length; i++) {
            concatenatedData[newX.length + i] = X[i];
        }

        // Copy the right-encoded output length into the concatenatedData array
        byte[] encodedL = right_encode(BigInteger.valueOf(L));
        for (int i = 0; i < encodedL.length; i++) {
            concatenatedData[newX.length + X.length + i] = encodedL[i];
        }

        // Call cSHAKE256 with the prepared input
        return cSHAKE256(concatenatedData, L, N, S);
    }

    /**
     * Encode an integer as a byte array in a way that can be parsed from the end of the string.
     *
     * @param x The integer to encode.
     * @return The byte array representing the encoded integer.
     * @throws IllegalArgumentException if the input value is out of range.
     */
    public static byte[] right_encode(BigInteger x) {
        // Check if the input value is out of range
        if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(BigInteger.valueOf(2).pow(2040)) >= 0) {
            throw new IllegalArgumentException("Input value out of range");
        }

        // Special case for zero
        if (x.compareTo(BigInteger.ZERO) == 0) {
            return new byte[]{0, 1}; // Return a byte array with length 2 and value 0x00 0x01
        }

        // Determine the number of bytes needed to represent x
        int numBytes = (x.bitLength() + 7) / 8;
        // Create a byte array of appropriate size
        byte[] result = new byte[numBytes + 1];

        // Encode the length of the byte array
        result[0] = (byte) numBytes;

        // Encode the integer into the byte array in little-endian format
        for (int i = numBytes; i > 0; i--) {
            // Extract the least significant byte of x and store it in the byte array
            result[i] = x.and(BigInteger.valueOf(0xFF)).byteValue();
            // Shift x to the right by 8 bits to process the next byte
            x = x.shiftRight(8);
        }

        return result;
    }

    /**
     * Encode a bit string in a way that can be parsed unambiguously from the beginning of the string.
     *
     * @param S The input bit string as a byte array.
     * @return The encoded bit string as a byte array.
     */
    public static byte[] encode_string(byte[] S) {
        // Check the validity condition
        if (S.length >= Math.pow(2, 2040)) {
            throw new IllegalArgumentException("Input string length exceeds maximum allowed value.");
        }

        // Convert the length of the input string to BigInteger
        BigInteger length = BigInteger.valueOf(S.length);

        // Encode the length of the string using left_encode
        byte[] lenEncoded = left_encode(length);

        // Concatenate the encoded length and the string bytes
        byte[] encoded = new byte[lenEncoded.length + S.length];

        // Copy the bytes of lenEncoded to the beginning of encoded array
        for (int i = 0; i < lenEncoded.length; i++) {
            encoded[i] = lenEncoded[i];
        }

        // Copy the bytes of S to the remaining space in encoded array
        for (int i = 0; i < S.length; i++) {
            encoded[lenEncoded.length + i] = S[i];
        }

        return encoded;
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

}




