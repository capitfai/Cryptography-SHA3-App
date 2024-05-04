/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Part 1: Our implementation pulls inspiration from:
 * Markku-Juhani O. Saarinen
 * <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws IOException {

        if (args.length < 3) {
            System.out.println("Usage: java Main <input_file> <output file> <password>");
            System.exit(1);
        }

        String inputPath = args[0];
        String outputPath = args[1];
        String passphrase = args[2];

        String input = readInputFile(inputPath);
        String pw = readInputFile(passphrase);
        handleUserInput(input, outputPath, pw);

    }

    private static String readInputFile(String TheInputPath) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(TheInputPath));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        return sb.toString();
    }

    private static void writeStringToFile(String TheString, String TheFilePath) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(TheFilePath))) {
            bw.write(TheString);
        }
    }

    private static void writeBytesToFile(byte[] data, String TheFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(TheFilePath)) {
            fos.write(data);
        }
    }

    public static void handleUserInput(String theInputFile, String theOutputPath,
                                       String thePassPhrase) throws IOException {
        byte[] input = Files.readAllBytes(Paths.get(theInputFile));
        byte[] pw = thePassPhrase.getBytes();

        System.out.println("Welcome to SHA3 App! Please select the method you would like to use "
            + "by typing the number of the option below: \n");
        System.out.println("1. Compute a hash of a file.");
        System.out.println("2. Compute a hash of a given text.");
        System.out.println("3. Compute an authentication tag of a file.");
        System.out.println("4. Compute an authentication tag of a given text.");
        System.out.println("5. Encrypt a file.");
        System.out.println("6. Encrypt a given text.");
        System.out.println("7. Decrypt a file.");
        System.out.println("8. Decrypt a given text.");
        System.out.println("9. Exit.");

        int choice = scanner.nextInt();

        while (choice < 1 && choice > 7) {
            System.out.println("Choice is not listed. Please select a method you would like to use: \n");
            choice = scanner.nextInt();
        }

        scanner.nextLine();

        switch (choice) {
            case 1 -> {
                byte[] hashResult = computeHash(input);         // stores result into separate byte array
                if (hashResult != null) {
                    printByteArray(hashResult);                 // prints to console
                }
                writeBytesToFile(hashResult, theOutputPath);
            }
            case 2 -> {
                byte[] hashInput = handleInputToBytes();
                byte[] hashResult = computeHash(hashInput);     // stores result into separate byte array
                if (hashResult != null) {
                    printByteArray(hashInput);                  // prints to console
                }
                writeBytesToFile(hashInput, theOutputPath);
            }
            case 3 -> {
                byte[] tag = computeTag(input, pw);
                if (tag != null) {
                    printByteArray(tag);
                }
                writeBytesToFile(tag, theOutputPath);
            }
            case 4 -> {
                byte[] tagInput = handleInputToBytes();
                byte[] pwInput = handleInputToBytes();
                byte[] tag = computeTag(tagInput, pwInput);
                if (tag != null) {
                    printByteArray(tag);
                }
                writeBytesToFile(tag, theOutputPath);
            }
            case 5 -> {
                byte[] encrypted = encrypt(input, pw);
                printByteArray(encrypted);                      // prints to console
                writeBytesToFile(encrypted, theOutputPath);
            }
            case 6 -> {
                byte[] encryptInput = handleInputToBytes();
                byte[] selected_pw = handleInputToBytes();
                byte[] encrypted = encrypt(encryptInput, selected_pw);
                printByteArray(encrypted);
                writeBytesToFile(encrypted, theOutputPath);
            }
            case 7 -> decrypt(input, pw, theOutputPath);
            case 8 -> {
                System.out.println("Exiting SHA3 App.");
                System.exit(0);
            }
        }
    }

    // Supporting method that ensures input is accurately typed.
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

    public static void printByteArray(byte[] TheArray) {
        for (byte b : TheArray) {
            System.out.print(b + " ");
        }
    }

    public static byte[] randomizeBits(int theNumBits) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[theNumBits / 8];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    public static byte[] XOR(byte[] TheArrayOne, byte[] TheArrayTwo) {
        byte[] result = new byte[Math.min(TheArrayOne.length, TheArrayTwo.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (TheArrayOne[i] ^ TheArrayTwo[i]);
        }
        return result;
    }

    private static String bytesToHex(byte[] theBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : theBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] computeHash(byte[] m) {
        return sha3.KMACXOF256("".getBytes(), m, 512, "D".getBytes());
    }

    private static byte[] computeTag(byte[] m, byte[] pw) {
        return sha3.KMACXOF256(pw, m, 512, "T".getBytes());
    }

    // Takes input and passphrase, encrypts,
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

        return result;
    }

    private static void decrypt(byte[] zct, byte[] pw, String TheOutputFile) throws IOException {
        byte[] z = Arrays.copyOfRange(zct, 0, 64);
        byte[] c = Arrays.copyOfRange(zct, 64, zct.length - 64); // middle???
        byte[] t = Arrays.copyOfRange(zct, zct.length - 64, zct.length);

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
