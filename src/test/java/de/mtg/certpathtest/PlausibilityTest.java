
package de.mtg.certpathtest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Contains simple tests to check whether the paths created by the tool are meaningful.
 *
 */
public class PlausibilityTest
{
    /**
     *
     * Runs tests to check whether the paths created by the tool are meaningful.
     *
     * @param args any optional argument.
     * @throws IOException if an IOException occurs.
     */
    public static void main(String[] args) throws IOException
    {

        Security.addProvider(new BouncyCastleProvider());

        Files.walkFileTree(Paths.get("testOutput"), new OutputReaderPathConstruction(null));

    }
}
