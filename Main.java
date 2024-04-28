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


//        switch (command) {
//            case "hash" -> {
//                if (args.length != 2) {
//                    System.out.println("Usage: Main hash function fail.");
//                    return;
//                }
//                computeHash(args[1]);
//            }
//            case "tag" -> {
//                if (args.length != 3) {
//                    System.out.println("Usage: Main tag function fail.");
//                    return;
//                }
//                computeTag(args[1], args[2]);
//            }
//            case "encrypt" -> {
//                if (args.length != 3) {
//                    System.out.println("Usage: Main encrypt file failed.");
//                    return;
//                }
//                encrypt(args[1], args[2]);
//            }
//            case "decrypt" -> {
//                if (args.length != 3) {
//                    System.out.println("Usage: Main decrypt function failed.");
//                    return;
//                }
//                decrypt(args[1], args[2]);
//            }
//            default -> System.out.println("Invalid command.");
//        }

    }

    private static String bytesToHex(byte[] theBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : theBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] computeHash(byte[] theInputBytes) {
        // TODO: call hash function
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

    // private file utility class

//    private static class FileUtility {
//
//        public static byte[] readFile(String theFileName) {
//            try {
//                FileInputStream fis = new FileInputStream(theFileName);
//                ByteArrayOutputStream bos = new ByteArrayOutputStream();
//                byte[] buffer = new byte[1024];
//                int bytesRead;
//                while ((bytesRead = fis.read(buffer)) != -1) {
//                    bos.write(buffer, 0, bytesRead);
//                }
//                fis.close();
//                return bos.toByteArray();
//            } catch (IOException e) {
//                e.printStackTrace();
//                return new byte[0];
//            }
//        }
//
//        public static void writeFile(String theFileName, byte[] theData) {
//            try {
//                FileOutputStream fos = new FileOutputStream(theFileName);
//                fos.write(theData);
//                fos.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//
//        public static void writeEncryptedFile(String theFileName, byte[][] theData) {
//            try {
//                FileOutputStream fos = new FileOutputStream(theFileName);
//                for (byte[] array: theData) {
//                    fos.write(array);
//                }
//                fos.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//
//        public static byte[][] readEncryptedFile(String theFileName) {
//            try {
//                FileInputStream fis = new FileInputStream(theFileName);
//                ByteArrayOutputStream bos = new ByteArrayOutputStream();
//                byte[] buffer = new byte[1024];
//                int bytesRead;
//                while ((bytesRead = fis.read(buffer)) != -1) {
//                    bos.write(buffer, 0, bytesRead);
//                }
//                fis.close();
//                byte[] data = bos.toByteArray();
//                int splitIndex = data.length / 3;
//                byte[][] result = new byte[3][];
//                result[0] = Arrays.copyOfRange(data, 0, splitIndex);
//                result[1] = Arrays.copyOfRange(data, splitIndex, 2 * splitIndex);
//                result[2] = Arrays.copyOfRange(data, 2 * splitIndex, data.length);
//                return result;
//            } catch (IOException e) {
//                e.printStackTrace();
//                return new byte[0][];
//            }
//        }
//    }

}
