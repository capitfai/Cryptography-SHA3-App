/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import javax.swing.plaf.synth.SynthStyle;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Part 1: Our implementation pulls inspiration from:
 * Markku-Juhani O. Saarinen
 * <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {

        if (args.length < 4) {
            System.out.printf("Unknown command %s", args[0]);
            System.exit(1);
        }

        final String command = args[0].toLowerCase();

        switch (command) {
            case "hash":
                if(args.length != 2) {
                    System.out.println("Usage: Main hash function fail.");
                    return;
                }
                //computeHash(args[1]);
                break;
            case "tag":
                if(args.length != 3) {
                    System.out.println("Usage: Main tag function fail.");
                    return;
                }
                //computeTag(args[1], args[2]);
                break;
            case "encrypt":
                if (args.length != 3) {
                    System.out.println("Usage: Main encrypt file failed.");
                    return;
                }
//                encrypt(args[1], args[2]);
                break;
            case "decrypt":
                if (args.length != 3) {
                    System.out.println("Usage: Main decrypt function failed.");
                    return;
                }
//                decrypt(args[1], args[2]);
                break;
            default:
                System.out.println("Invalid command.");
        }

    }

    private static void computeHash(String theFileName) {
        byte[] filesBytes = FileUtility.readFile(theFileName);
        // TODO: call hash function
//        System.out.println("Hash: " + Arrays.toString(hash));
    }

    private static void computeTag(String thePassphrase, String theFileName) {
        byte[] fileBytes = FileUtility.readFile(theFileName);
//        byte[] tag = AutheticationTag.computeTag(thePassphrase.getBytes(), fileBytes);
//        System.out.println("Tag: " + Arrays.toString(tag));
    }

    private static void encrypt(String thePassphrase, String theFileName) {
        byte[] fileBytes = FileUtility.readFile(theFileName);
//        byte[][] cryptogram = SymmetricEncryption.encrypt(filesBytes, thePassphrase.getBytes());
//        FileUtility.writeEncryptedFile(theFileName + ".encrypted" + cryptogram);
        System.out.println("Encrypted file: " + theFileName + ".encrypted");
    }

    private static void decrypt(String thePassphrase, String theFileName) {
        byte[][] cryptogram = FileUtility.readEncryptedFile(theFileName);
//        byte[] decryptedBytes = SymmetricEncryption.decrypt(cryptogram, thePassphrase.getBytes());
//        FileUtility.writeFile(theFileName.replace(".encrypted", "", decryptedBytes))
        System.out.println("Decrypted File: " + theFileName.replace(".encrypted", ""));
    }

    // private file utility class

    private static class FileUtility {

        public static byte[] readFile(String theFileName) {
            try {
                FileInputStream fis = new FileInputStream(theFileName);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }
                fis.close();
                return bos.toByteArray();
            } catch (IOException e) {
                e.printStackTrace();
                return new byte[0];
            }
        }

        public static void writeFile(String theFileName, byte[] theData) {
            try {
                FileOutputStream fos = new FileOutputStream(theFileName);
                fos.write(theData);
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static void writeEncryptedFile(String theFileName, byte[][] theData) {
            try {
                FileOutputStream fos = new FileOutputStream(theFileName);
                for (byte[] array: theData) {
                    fos.write(array);
                }
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static byte[][] readEncryptedFile(String theFileName) {
            try {
                FileInputStream fis = new FileInputStream(theFileName);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }
                fis.close();
                byte[] data = bos.toByteArray();
                int splitIndex = data.length / 3;
                byte[][] result = new byte[3][];
                result[0] = Arrays.copyOfRange(data, 0, splitIndex);
                result[1] = Arrays.copyOfRange(data, splitIndex, 2 * splitIndex);
                result[2] = Arrays.copyOfRange(data, 2 * splitIndex, data.length);
                return result;
            } catch (IOException e) {
                e.printStackTrace();
                return new byte[0][];
            }
        }
    }

}
