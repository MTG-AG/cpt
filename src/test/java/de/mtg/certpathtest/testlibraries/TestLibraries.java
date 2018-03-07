
package de.mtg.certpathtest.testlibraries;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.FileAppender;

/**
 * It is used for testing the implementation of certification path construction and validation of cryptographic
 * providers.
 *
 */
public class TestLibraries
{
    private static Logger logger;

    private static String provider = null;

    /**
     *
     * Runs the tests for the java libraries.
     *
     * Use -Djava.security.debug=certpath if more debug information is necessary.
     *
     * @param args the arguments to run this VM. First argument is the output directory of the tool and the second
     *            optional argument the name of the provider to be tested.
     */
    public static void main(String[] args)
    {

        if (!(args.length == 1 || args.length == 2))
        {
            System.err.println("Wrong number of arguments.");
            System.err.println("Usage: java de.mtg.certpathtest.testlibraries.TestLibraries <test tool output directory> <provider name>(optional)");
            System.exit(0);
        }

        String path = args[0];

        if (path == null || path.isEmpty())
        {

        }

        Path testCaseDir = Paths.get(path);

        if (!Files.exists(testCaseDir) || !Files.isDirectory(testCaseDir))
        {
            System.err.println(args[0] + " does not exist or is a not a directory.");
            System.exit(0);
        }

        if (args.length != 2)
        {
            provider = null;
        }
        else
        {
            provider = args[1];

            Provider jcaProvider = Security.getProvider(provider);
            if (jcaProvider == null) {
                System.err.println("Provider "+provider+" must be installed statically. For dynamic installation please modify the program.");
                System.exit(0);
            }
        }

        String pattern = "%date %-8([%level]) %msg%n";

        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

        PatternLayoutEncoder filePatternLayoutEncoder = new PatternLayoutEncoder();
        filePatternLayoutEncoder.setContext(loggerContext);
        filePatternLayoutEncoder.setPattern(pattern);
        filePatternLayoutEncoder.start();

        FileAppender<ILoggingEvent> logFileAppender = new FileAppender<ILoggingEvent>();
        logFileAppender.setContext(loggerContext);
        logFileAppender.setEncoder(filePatternLayoutEncoder);
        logFileAppender.setAppend(true);
        logFileAppender.setFile("testLibraries.log");
        logFileAppender.start();

        logger = loggerContext.getLogger("de");
        logger.setAdditive(false);
        logger.setLevel(Level.valueOf("DEBUG"));
        logger.addAppender(logFileAppender);

        // PatternLayoutEncoder consolePatternLayoutEncoder = new PatternLayoutEncoder();
        // consolePatternLayoutEncoder.setContext(loggerContext);
        // consolePatternLayoutEncoder.setPattern(pattern);
        // consolePatternLayoutEncoder.start();
        // ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
        // consoleAppender.setContext(loggerContext);
        // consoleAppender.setEncoder(consolePatternLayoutEncoder);
        // consoleAppender.start();
        // logger.addAppender(consoleAppender);

        logger.info("Starting of logging.");

        File outputDir = new File(path);

        List<String> filenames = new ArrayList<String>();

        for (String testCase : outputDir.list())
        {
            filenames.add(testCase);
        }

        Collections.sort(filenames);

        for (String testCase : filenames)
        {
            File testCaseFile = new File(outputDir, testCase);
            if (testCaseFile.isDirectory())
            {
                logger.info("Working on test case: " + testCase);
                try
                {

                    String reference = processTestCaseWithConstruction(testCaseFile, false);
                    for (int i = 0; i < 15; i++)
                    {
                        String output = processTestCaseWithConstruction(testCaseFile, false);
                        if (!reference.equalsIgnoreCase(output))
                        {
                            System.err.println("ERROR.");
                            System.exit(0);
                        }
                    }

                    processTestCaseWithConstruction(testCaseFile, true);

                }
                catch (Exception e)
                {
                    logger.info("", e);
                }
            }

        }

    }

    private static String extractTestCaseId(String filename) throws IOException
    {
        return extractLine(filename, "Test Case");
    }

    private static String extractExpectedResult(String filename) throws IOException
    {
        return extractLine(filename, "Expected Result");
    }

    private static String extractTestDescription(String filename) throws IOException
    {
        return extractLine(filename, "Purpose");
    }

    private static String extractSeverity(String filename) throws IOException
    {
        return extractLine(filename, "Severity");
    }

    private static String extractLine(String filename, String lineStart) throws IOException
    {

        List<String> lines = Files.readAllLines(Paths.get(filename));

        for (String line : lines)
        {
            line = line.trim();
            if (line.startsWith(lineStart))
            {
                return (line.split(Pattern.quote(":"))[1]).trim();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static String processTestCaseWithConstruction(File testCaseDirectory, boolean print)
                    throws CertificateException, NoSuchProviderException, IOException,
                    InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException,
                    CRLException, CertPathBuilderException, KeyStoreException
    {

        StringBuilder stringBuilder = new StringBuilder();

        String expectedResult = null;
        String testCaseId = null;
        String testDescription = null;
        String outputResult = null;
        String result = null;
        String error = null;
        String severity = null;

        boolean decodingError = false;

        for (String filename : testCaseDirectory.list())
        {

            if (filename.endsWith("testReport.txt"))
            {
                File file = new File(testCaseDirectory, filename);
                expectedResult = extractExpectedResult(file.getPath());
                testCaseId = extractTestCaseId(file.getPath());
                testDescription = extractTestDescription(file.getPath());
                severity = extractSeverity(file.getPath());
            }
        }

        try
        {

            X509Certificate trustAnchor = null;
            X509Certificate targetCertificate = null;
            List<X509CRL> crls = new ArrayList<>();
            List<X509Certificate> caCertificates = new ArrayList<>();

            CertificateFactory certificateFactory = null;

            if (provider == null)
            {
                certificateFactory = CertificateFactory.getInstance("X.509");
            }
            else
            {
                certificateFactory = CertificateFactory.getInstance("X.509", provider);
            }

            Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();

            int targetCertificateCounter = 0;

            boolean revocationCheckingEnabled = false;

            for (String filename : testCaseDirectory.list())
            {
                File file = new File(testCaseDirectory, filename);
                logger.info(file.toString());

                if (filename.equalsIgnoreCase("crls"))
                {
                    logger.info("For this test case revocation checking is enabled.");
                    revocationCheckingEnabled = true;

                    for (String crlFilename : file.list())
                    {
                        if (!crlFilename.endsWith(".pem.crl"))
                        {
                            File crlFile = new File(file, crlFilename);
                            FileInputStream fis = new FileInputStream(crlFile);
                            X509CRL crl = null;
                            try
                            {
                                crl = (X509CRL) certificateFactory.generateCRL(fis);
                            }
                            catch (Exception e)
                            {
                                decodingError = true;
                                throw e;
                            }
                            crls.add(crl);
                            fis.close();
                        }
                    }

                }

                if (filename.endsWith(".TA.crt"))
                {
                    FileInputStream fis = new FileInputStream(file);
                    try
                    {
                        trustAnchor = (X509Certificate) certificateFactory.generateCertificate(fis);
                    }
                    catch (Exception e)
                    {
                        decodingError = true;
                        throw e;
                    }
                    fis.close();
                }

                if (filename.endsWith(".TC.crt"))
                {
                    FileInputStream fis = new FileInputStream(file);
                    try
                    {
                        targetCertificate = (X509Certificate) certificateFactory.generateCertificate(fis);
                    }
                    catch (Exception e)
                    {
                        decodingError = true;
                        throw e;
                    }
                    fis.close();
                    targetCertificateCounter += 1;
                }

                if (filename.endsWith(".CA.crt"))
                {
                    FileInputStream fis = new FileInputStream(file);
                    try
                    {
                        caCertificates.add((X509Certificate) certificateFactory.generateCertificate(fis));
                    }
                    catch (Exception e)
                    {
                        decodingError = true;
                        throw e;
                    }
                    fis.close();
                }

            }

            if (targetCertificateCounter != 1)
            {
                logger.error("Did not find exactly one target certificate for this test case.");
            }

            PKIXParameters params = null;
            if (trustAnchor != null)
            {
                anchors.add(new TrustAnchor(trustAnchor, null));
                params = new PKIXParameters(anchors);
            }

            @SuppressWarnings("rawtypes")
            ArrayList certsAndCrls = new ArrayList();

            // add CRLs
            if (revocationCheckingEnabled && !crls.isEmpty())
            {
                for (X509CRL crl : crls)
                {
                    certsAndCrls.add(crl);
                }
            }

            // add intermediate certificates

            // add CRLs
            if (!caCertificates.isEmpty())
            {
                int size = caCertificates.size();
                int upperBound = size;
                Random random = new Random();
                for (int i = 0; i < size; i++)
                {
                    int r = random.nextInt(upperBound);
                    upperBound = upperBound - 1;
                    certsAndCrls.add(caCertificates.get(r));
                    caCertificates.remove(r);
                }

            }

            // add target certificate

            certsAndCrls.add(targetCertificate);

            CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(certsAndCrls);
            CertStore certStore = CertStore.getInstance("Collection", certStoreParams);

            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(targetCertificate);

            CertPathBuilder certPathBuilder = null;

            if (provider == null)
            {
                certPathBuilder = CertPathBuilder.getInstance("PKIX");
            }
            else
            {
                certPathBuilder = CertPathBuilder.getInstance("PKIX", provider);
            }

            PKIXBuilderParameters certPathBuilderParams = new PKIXBuilderParameters(anchors, certSelector);
            certPathBuilderParams.addCertStore(certStore);
            certPathBuilderParams.setRevocationEnabled(revocationCheckingEnabled);
            certPathBuilderParams.setSigProvider(provider);
            CertPathBuilderResult cpbResult = certPathBuilder.build(certPathBuilderParams);

            CertPath certPath = cpbResult.getCertPath();

            // Validation

            CertPathValidator cpv = null;

            if (provider == null)
            {
                cpv = CertPathValidator.getInstance("PKIX");
            }
            else
            {
                params.setSigProvider(provider);
                cpv = CertPathValidator.getInstance("PKIX", provider);
            }
            params.setRevocationEnabled(revocationCheckingEnabled);

            PKIXCertPathValidatorResult certPathValidatorResult =
                (PKIXCertPathValidatorResult) cpv.validate(certPath, params);

            if (certPathValidatorResult.getPublicKey() != null)
            {

                outputResult = "VALID";
                error = "-";
                if (expectedResult.equalsIgnoreCase("VALID"))
                {
                    result = "PASS";
                }
                else
                {
                    result = severity;
                }
            }

        }
        catch (Exception ex)
        {
            logger.error("", ex);

            if (decodingError)
            {
                outputResult = "Dekodierungsfehler";
            }
            else
            {
                outputResult = "INVALID";
            }

            error = ex.getMessage();

            if (expectedResult.equalsIgnoreCase("INVALID"))
            {
                result = "PASS";
            }
            else
            {
                result = severity;

            }

        }

        // stringBuilder.append(String.format("%26s", testCaseId));
        // stringBuilder.append("|");
        // stringBuilder.append(String.format("%5s", result));
        // stringBuilder.append("|");
        // stringBuilder.append(String.format("%7s", expectedResult));
        // stringBuilder.append("|");
        // stringBuilder.append(String.format("%7s", outputResult));
        // stringBuilder.append("|");
        // stringBuilder.append(String.format("%80s", error));
        // stringBuilder.append("|");
        // stringBuilder.append(testDescription);

        stringBuilder.append(testCaseId);
        stringBuilder.append("|");
        stringBuilder.append(result);
        stringBuilder.append("|");
        stringBuilder.append(expectedResult);
        stringBuilder.append("|");
        stringBuilder.append(outputResult);
        stringBuilder.append("|");
        stringBuilder.append(error);
        stringBuilder.append("|");
        stringBuilder.append(testDescription);

        if (print)
        {
            System.out.println(stringBuilder.toString());
        }

        return stringBuilder.toString();

    }

}
