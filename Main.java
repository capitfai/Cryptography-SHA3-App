/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class Main {

    public static void main(String[] args) throws IOException {

        // TODO: Look at past assignment.
        FileWriter out = new FileWriter(args[2]);
        if (args[0].equals("c")) {

            Path path = Paths.get(args[1]);
            Stream<String> stringStream = Files.lines(path);
        }

    }
}
