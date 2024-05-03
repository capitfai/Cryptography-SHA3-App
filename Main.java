/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Part 1: Our implementation pulls inspiration from:
 * Markku-Juhani O. Saarinen
 * <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 */
public class Main {

    public static void main(String[] args) {

        if (args.length != 3) {
            System.err.println("Usage: java Main <input_file> <output file> <password>");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];
        String passphrase = args[2];

        final Path output = Paths.get(outputFile);

        try {
            byte[] input = Files.readAllBytes(Paths.get(inputFile));

            byte[] hash = computeHash(input);
            System.out.println("Hash: " + bytesToHex(hash));

            byte[] tag = computeTag(input, passphrase);
            System.out.println("Tag: " + bytesToHex(tag));

            byte[] encrypted = encrypt(input, passphrase);
            Files.write(output, encrypted);
            System.out.println("Encrypted Successfully. Output written to: " + outputFile);

            byte[] decrypted = decrypt(encrypted, passphrase);
            Files.write(output, decrypted);
            System.out.println("Decrypted Successfully. Output written to: " + outputFile);

        } catch (IOException e) {
            System.out.println("Error reading input file.");
        }

    }

    private static String bytesToHex(byte[] theBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : theBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] computeHash(byte[] theInputBytes) {
        return null;
    }

    private static byte[] computeTag(byte[] theBytes, String thePassphrase) {
        return null;
    }

    private static byte[] encrypt(byte[] theBytes, String thePassphrase) {
        return null;
    }

    private static byte[] decrypt(byte[] theData, String thePassphrase) {
        return null;
    }



}
