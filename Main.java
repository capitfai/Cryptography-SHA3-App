/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

/**
 * Part 1: Our implementation pulls inspiration from:
 * Markku-Juhani O. Saarinen
 * <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 */
public class Main {

    /**
     * Scanner to read user input.
     */
    private static final Scanner scanner = new Scanner(System.in);

    /**
     * Container for keeping the concatenated zct bytes for encrypt/decrypt.
     */
    public static ArrayList<byte[]> zct;

    public static EncryptedData ellipticEncryption;

    /**
     * Value storing computed private key.
     */
    private static BigInteger privateKey;

    /**
     * Value storing computed public key.
     */
    private static Ed448Point publicKey;

    private static final BigInteger r = (BigInteger.TWO).pow(446).subtract(
            new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    private static final BigInteger P =
            BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);

    /**
     * Driver method that kicks off program and takes in string arguments for files.
     * @param args String arguments.
     * @throws IOException For file reading.
     */
    public static void main(String[] args) throws IOException {

        zct = new ArrayList<>();
        if (args.length < 4) {
            System.out.println("Usage: java Main <input_file_path> <output_file_path> <passphrase_path> " +
                    "<private_key_path");
            System.exit(1);
        }

        String inputName = args[0];
        String outputName = args[1];
        String passphrase = args[2];
        String privateKey = args[3];

        String input = readInputFile(inputName);
        String pw = readInputFile(passphrase);
        String key = readInputFile(privateKey);
        handleUserInput(input, outputName, pw, key);

    }

    /**
     * Reads the file input name and parses through the text.
     * @param theInputName Name of file name.
     * @return Concatenated String of what is in the file.
     * @throws IOException For reading files.
     */
    private static String readInputFile(String theInputName) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(theInputName));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        return sb.toString();
    }

    /**
     * Writes to the output file specified in the parameter.
     * @param TheString The given string we want to write.
     * @param theFileName The name of file output.
     * @throws IOException For reading files.
     */
    private static void writeStringToFile(String TheString, String theFileName) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(theFileName))) {
            bw.write(TheString);
        }
    }

    /**
     * After starting the program, this is the central method that will keep prompting for input and call the
     * appropriate methods depending on the method specified.
     * @param TheInputFile The contents of the input file.
     * @param TheOutputFile The name of the output file.
     * @param ThePassphraseFile The name of the passphrase file.
     * @throws IOException For reading files.
     */
    public static void handleUserInput(String TheInputFile, String TheOutputFile,
                                       String ThePassphraseFile, String TheKeyFile) throws IOException {
        byte[] input = TheInputFile.getBytes();
        byte[] pw = ThePassphraseFile.getBytes();
        System.out.println("Welcome to SHA3 App! \n");

        int choice;
        while (true) {
            System.out.println("Please select the method you would like to use by typing the number of the option below: \n" );
            System.out.println("1. Compute a hash of a file.");
            System.out.println("2. Compute a hash of a given text.");
            System.out.println("3. Compute an authentication tag of a file.");
            System.out.println("4. Compute an authentication tag of a given text.");
            System.out.println("5. Encrypt a file.");
            System.out.println("6. Encrypt a given text.");
            System.out.println("7. Decrypt a file.");
            System.out.println("8. Generate an elliptic key pair");
            System.out.println("9. Encrypt a file under elliptic public key.");
            System.out.println("10. Encrypt a given text under elliptic public key.");
            System.out.println("11. Decrypt elliptic-encrypted file from passphrase.");
            System.out.println("12. Generate a signature file.");
            System.out.println("13. Generate a signature file under given text.");
            System.out.println("14. Verify a file.");
            System.out.println("15. Verify a given text.");
            System.out.println("16. Exit.");
            choice = scanner.nextInt();
            scanner.nextLine();
            switch (choice) {
                case 1 -> {
                    byte[] hashResult = computeHash(input);         // stores result into separate byte array
                    if (hashResult != null) {
                        String str = bytesToHex(hashResult);
                        System.out.println(str + "\n");                 // prints to console
                        writeStringToFile(str, TheOutputFile);
                    }
                }
                case 2 -> {
                    System.out.println("Please enter the input you want to hash: \n");
                    byte[] hashInput = handleInputToBytes();
                    byte[] hashResult = computeHash(hashInput);     // stores result into separate byte array
                    if (hashResult != null) {
                        String str = bytesToHex(hashResult);
                        System.out.println(str);                 // prints to console
                        writeStringToFile(str, TheOutputFile);
                    }
                }
                case 3 -> {
                    byte[] tag = computeTag(input, pw);
                    if (tag != null) {
                        String str = bytesToHex(tag);
                        System.out.println(str);                 // prints to console
                        writeStringToFile(str, TheOutputFile);
                    }
                }
                case 4 -> {
                    System.out.println("Please enter the input you want to tag: \n");
                    byte[] tagInput = handleInputToBytes();
                    System.out.println("Please enter the password: \n");
                    byte[] pwInput = handleInputToBytes();
                    byte[] tag = computeTag(tagInput, pwInput);
                    if (tag != null) {
                        String str = bytesToHex(tag);
                        System.out.println(str);                 // prints to console
                        writeStringToFile(str, TheOutputFile);
                    }
                }
                case 5 -> {
                    byte[] encrypted = encrypt(input, pw);
                    String str = bytesToHex(encrypted);
                    System.out.println(str);                 // prints to console
                    writeStringToFile(str, TheOutputFile);
                }
                case 6 -> {
                    System.out.println("Please enter the input you want to encrypt: \n");
                    byte[] encryptInput = handleInputToBytes();
                    System.out.println("Please enter the passphrase you want to use: \n");
                    byte[] selected_pw = handleInputToBytes();
                    byte[] encrypted = encrypt(encryptInput, selected_pw);
                    String str = bytesToHex(encrypted);
                    System.out.println(str);                 // prints to console
                    writeStringToFile(str, TheOutputFile);
                }
                case 7 -> decrypt(pw, TheOutputFile);
                case 8 -> {
                    generateKeyPair(pw);
                    writeStringToFile(publicKey.toString(), TheOutputFile);     // writes public key to file
                    byte[] encrypted = encrypt(privateKey.toByteArray(), pw);
                    String str = bytesToHex(encrypted);
                    writeStringToFile(str, TheKeyFile);     // writes private encrypted key to different file
                }
                case 9 -> {
                    if (publicKey != null) {
                        encryptWithKey(input, TheOutputFile);
                    } else {
                        System.out.println("Key generation must be completed first.");
                    }
                }
                case 10 -> {
                    // Encrypt text input by the user directly to the app instead of
                    // having to read it from a file (but write the ciphertext to a file).
                }
                case 11 -> {
                    // Decrypt a given elliptic-encrypted file from a given password and
                    // write the decrypted data to a file.
                }
                case 12 -> {
                    // Sign a given file from a given password and write the signature to
                    // a file.
                }
                case 13 -> {
                    // Sign text input by the user directly to the app instead of
                    // having to read it from a file (but write the signature to a file).
                }
                case 14 -> {
                    // Verify a given data file and its signature file under a given public
                    // key file.
                }
                case 15 -> {
                    //Verify text input by the user directly to the app instead of
                    //having to read it from a file (but read the signature from a file).
                }
                case 16 -> {
                    System.out.println("Exiting SHA3 App.");
                    System.exit(0);
                }
                default -> System.out.println("Choice is not listed. Please select a method you would like to use: \n");
            }
        }
    }

    /**
     * Ensures that user input is valid and converts to a byte array for further processing.
     * @return byte array for methods to use easier.
     */
    public static byte[] handleInputToBytes() {
        byte[] validInput;
        String userInput = scanner.nextLine();

        while (userInput == null) {
            System.out.println("Please type valid text. \n");
            userInput = scanner.nextLine();
        }
        validInput = userInput.getBytes();
        return validInput;
    }

    /**
     * Prints the byte array to console (debugging).
     * @param TheArray Byte array to be printed.
     */
    public static void printByteArray(byte[] TheArray) {
        for (byte b : TheArray) {
            System.out.print(b + " ");
        }
    }

    /**
     * Uses SecureRandom to randomize bits of a given size.
     * @param theNumBits Size requested of a randomized byte array.
     * @return randomized byte array.
     */
    public static byte[] randomizeBits(int theNumBits) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[theNumBits / 8];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * XORs the two arrays' bits.
     * @param TheArrayOne First array to XOR.
     * @param TheArrayTwo Second array to XOR.
     * @return result of the two arrays after XOR operation.
     */
    public static byte[] XOR(byte[] TheArrayOne, byte[] TheArrayTwo) {
        byte[] result = new byte[Math.min(TheArrayOne.length, TheArrayTwo.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (TheArrayOne[i] ^ TheArrayTwo[i]);
        }
        return result;
    }

    /**
     * Converts the byte arrays to hex (for display and writing to file).
     * @param theBytes The byte array.
     * @return String of hex converted from bytes.
     */
    private static String bytesToHex(byte[] theBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : theBytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString().trim().toUpperCase();
    }

    /**
     * Calls the KMACXOF256 function to compute hash.
     * @param m Data input in bytes.
     * @return byte array.
     */
    private static byte[] computeHash(byte[] m) {
        return sha3.KMACXOF256("".getBytes(), m, 512, "D".getBytes());
    }

    /**
     * Calls the KMACXOF256 function to compute tag.
     * @param m Data input in bytes.
     * @param pw Password in bytes.
     * @return byte array.
     */
    private static byte[] computeTag(byte[] m, byte[] pw) {
        return sha3.KMACXOF256(pw, m, 512, "T".getBytes());
    }

    /**
     * Encrypts the given input using the passphrase under SHA3 algorithm.
     * @param m data input in bytes.
     * @param pw passphrase in bytes.
     * @return byte array of the encrypted result.
     */
    private static byte[] encrypt(byte[] m, byte[] pw) {
        byte[] z = randomizeBits(512);

        // concatenate z and pw
        byte[] concat = new byte[z.length + pw.length];
        System.arraycopy(z, 0, concat, 0, z.length);
        System.arraycopy(pw, 0, concat, pw.length, pw.length);

        // perform XOF function on z || pw
        byte[] concatKeys = sha3.KMACXOF256(concat, "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[concatKeys.length / 2];
        byte[] ka = new byte[concatKeys.length / 2];
        System.arraycopy(concatKeys, 0, ke, 0, ke.length);
        System.arraycopy(concatKeys, ke.length, ka, 0, ka.length);

        byte[] cKey = sha3.KMACXOF256(ke, "".getBytes(), m.length * 8, "SKE".getBytes());

        // c <- XOR'd bits
        byte[] c = XOR(cKey, m);

        byte[] t = sha3.KMACXOF256(ka, m, 512, "SKA".getBytes());

        byte[] result = new byte[z.length + c.length + t.length];
        System.arraycopy(z, 0, result, 0, z.length);
        System.arraycopy(c, 0, result, z.length, c.length);
        System.arraycopy(t, 0, result, z.length + c.length, t.length);
        zct.add(z);
        zct.add(c);
        zct.add(t);

        return result;
    }

    /**
     * Decrypts given the passphrase and encrypted bytes.
     * @param pw passphrase in bytes.
     * @param TheOutputFile name of output file.
     * @throws IOException For reading files.
     */
    private static void decrypt(byte[] pw, String TheOutputFile) throws IOException {
        if (zct.isEmpty()) {
            System.out.println("File has not yet been encrypted. Decryption cannot continue.");
        } else {
            byte[] z = zct.get(0);
            byte[] c = zct.get(1);
            byte[] t = zct.get(2);

            byte[] concat = new byte[z.length + pw.length];
            System.arraycopy(z, 0, concat, 0, z.length);
            System.arraycopy(pw, 0, concat, pw.length, pw.length);

            byte[] ke_ka = sha3.KMACXOF256(concat, "".getBytes(), 1024, "S".getBytes());
            byte[] ke = new byte[ke_ka.length / 2];
            byte[] ka = new byte[ke_ka.length / 2];
            System.arraycopy(ke_ka, 0, ke, 0, ke.length);
            System.arraycopy(ke_ka, ke.length, ka, 0, ka.length);

            byte[] mKey = sha3.KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE".getBytes());

            byte[] m = XOR(mKey, c);

            byte[] t_prime = sha3.KMACXOF256(ka, m, 512, "SKA".getBytes());

            if (Arrays.equals(t, t_prime)) {
                System.out.println("Decryption Successful!");
                String str = new String(m, StandardCharsets.UTF_8);
                System.out.println(str);
                writeStringToFile(str, TheOutputFile);
            } else {
                System.out.println("Decryption failed.");
                printByteArray(t);
                printByteArray(t_prime);
            }
        }
    }

    /**
     * Generates a (Schnorr/DHIES) key pair from passphrase pw.
     *
     * @param pw the passphrase.
     */
    public static void generateKeyPair(byte[] pw) {

        // Generate private key
        byte[] sBytes = sha3.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(sBytes);

        s = s.multiply(BigInteger.valueOf(4)).mod(r);

        // Generate public key
        BigInteger Gy = BigInteger.valueOf(-3).mod(P);
        Ed448Point G = new Ed448Point(false, Gy);
        Ed448Point V = G.multiply(s);

        privateKey = s;
        publicKey = V;

    }

    /**
     * Encrypts a byte array under (Schnorr/DHIES) public key.
     * @param m byte array input.
     */
    public static void encryptWithKey(byte[] m, String TheOutputFile) {

        Random ran = new Random();
        BigInteger k = new BigInteger(448, ran);
        k = k.multiply(BigInteger.valueOf(4)).mod(r);

        Ed448Point W = publicKey.multiply(k);
        Ed448Point Z = new Ed448Point(false, BigInteger.valueOf(-3).mod(P));

        byte[] Wx = W.getX().toByteArray();
        byte[] concat = new byte[Z.getX().toByteArray().length + Wx.length];
        System.arraycopy(Z.getX().toByteArray(), 0, concat, 0, Z.getX().toByteArray().length);
        System.arraycopy(Wx, 0, concat, Z.getX().toByteArray().length, Wx.length);

        byte[] ka_ke = sha3.KMACXOF256(Wx, "".getBytes(), (448 * 2), "PK".getBytes());

        byte[] ke = Arrays.copyOfRange(ka_ke, 0, 448 / 8);
        byte[] ka = Arrays.copyOfRange(ka_ke, 448 / 8, ka_ke.length);

        byte[] cKey = sha3.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
        byte[] c = XOR(cKey, m);

        byte[] t = sha3.KMACXOF256(ka, m, 448, "PKA".getBytes());

        ellipticEncryption = new EncryptedData(Z, c, t);

        try (BufferedWriter wr = new BufferedWriter(new FileWriter(TheOutputFile))) {
            wr.write(ellipticEncryption.getZ().toString() + bytesToHex(ellipticEncryption.getC())
                    + bytesToHex(ellipticEncryption.getT()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Helper class to store elliptically encrypted data (Z, c, t).
     */
    public static class EncryptedData {
        private final Ed448Point Z;
        private final byte[] c;
        private final byte[] t;

        public EncryptedData(Ed448Point Z, byte[] c, byte[] t) {
            this.Z = Z;
            this.c = c;
            this.t = t;
        }

        public Ed448Point getZ() {
            return Z;
        }

        public byte[] getC() {
            return c;
        }

        public byte[] getT() {
            return t;
        }
    }

}
