
package de.mtg.certpathtest.testcase.handlers;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.TestCase;

/**
 *
 * Implements the export of certificates revocation lists, and private keys on the filesystem under the output directory
 * specified by the user. It is the basic export function of the tool.
 *
 */
public class OutputHandler extends TestCaseHandler
{

    private static Logger logger = LoggerFactory.getLogger(OutputHandler.class);

    private TestCase testCase;

    public final static String TRUST_ANCHOR_FILE_ENDING = ".TA.crt";
    public final static String TARGET_CERTIFICATE_FILE_ENDING = ".TC.crt";
    public final static String CA_CERTIFICATE_FILE_ENDING = ".CA.crt";

    public final static String TRUST_ANCHOR_PEM_FILE_ENDING = ".TA.pem.crt";
    public final static String TARGET_CERTIFICATE_PEM_FILE_ENDING = ".TC.pem.crt";
    public final static String CA_CERTIFICATE_FILE_PEM_ENDING = ".CA.pem.crt";


    public final static String TARGET_PRIVATE_KEY_PEM_FILE_ENDING = ".TC.pem.key";



    /**
     *
     * Constructs a newly allocated OutputHandler object.
     *
     * @param testCase the file containing a test case for which the produced PKI objects are exported.
     */
    public OutputHandler(TestCase testCase)
    {
        super(testCase);
        this.testCase = testCase;
    }

    /**
     *
     * {@inheritDoc}
     *
     * Exports the certificates, revocation lists, and private keys on the filesystem under the output directory
     * specified by the user.
     *
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public void execute() throws IOException
    {

        String testCaseId = testCase.getId();
        ObjectCache objectCache = ObjectCache.getInstance();

        PKIObjects pkiObjects = objectCache.getPKIobjectsFromTestCase(testCaseId);

        String trustAnchorId = Utils.getTrustAnchorCertificateID(pkiObjects);
        String targetCertificateId = Utils.getTargetCertificateCertificateID(pkiObjects);

        List<String> certificateIds = objectCache.getCertificateIds(testCaseId);

        List<String> crlIds = objectCache.getCRLIds(testCaseId);
        List<String> ocspIds = objectCache.getOCSPResponsesIds(testCaseId);

        String outputDirectoryName =
            ConfigurationProperties.getInstance().getProperties()
                                   .getString(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY);

        Path path = Paths.get(outputDirectoryName, testCaseId);

        if (!path.toFile().exists())
        {
            path.toFile().mkdirs();
        }

        StringBuilder testCaseObjects = new StringBuilder();

        // Output certificates and private keys.

        for (String certificateId : certificateIds)
        {

            testCaseObjects.append(certificateId);
            testCaseObjects.append(System.getProperty("line.separator"));

            MDC.put("CERTIFICATE", certificateId);

            byte[] rawCertificate = objectCache.getRawCertificate(certificateId);

            if (rawCertificate == null)
            {
                Utils.logError("Certificate has not been issued.");
                ObjectCache.getInstance().addError("Certificate '" + certificateId + "' has not been issued.");
                continue;
            }

            String filename = certificateId;
            String pemFilename = certificateId;
            String p8Filename = certificateId;

            if (certificateId.equalsIgnoreCase(trustAnchorId))
            {
                filename = filename + TRUST_ANCHOR_FILE_ENDING;
                pemFilename = pemFilename + TRUST_ANCHOR_PEM_FILE_ENDING;
            }
            else if (certificateId.equalsIgnoreCase(targetCertificateId))
            {
                filename = filename + TARGET_CERTIFICATE_FILE_ENDING;
                pemFilename = pemFilename + TARGET_CERTIFICATE_PEM_FILE_ENDING;
            }
            else
            {
                filename = filename + CA_CERTIFICATE_FILE_ENDING;
                pemFilename = pemFilename + CA_CERTIFICATE_FILE_PEM_ENDING;
            }

            ConfigurationProperties.getInstance().getProperties()
                                   .getString(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY);

            logger.info("Exporting certificate.");
            Files.write(Paths.get(outputDirectoryName, testCaseId, filename), rawCertificate);
            Files.write(Paths.get(outputDirectoryName, testCaseId, pemFilename),
                        Utils.exportPEMCertificate(rawCertificate));
            logger.info("Successfully exported certificate.");

            logger.info("Exporting private key in PKCS8.");
            byte[] rawP8 = Utils.exportPKCS8(objectCache.getPrivateKey(certificateId));
            Files.write(Paths.get(outputDirectoryName, testCaseId, p8Filename + ".pem"), rawP8);

            if (certificateId.equalsIgnoreCase(targetCertificateId)) {
                Files.write(Paths.get(outputDirectoryName, testCaseId, p8Filename + TARGET_PRIVATE_KEY_PEM_FILE_ENDING), rawP8);
            }
            logger.info("Successfully exported private key to PKCS8.");

            MDC.remove("CERTIFICATE");
        }

        // Output crls

        // create CRL directory to notify the tester that revocation checking should be active. CRL may not be written
        // in this directory, therefore it must be created independently of any test case.
        if (testCaseId.indexOf("_CRL_") != -1)
        {
            Path crlOutputPath = Paths.get(outputDirectoryName, testCaseId, "crls");

            if (!crlOutputPath.toFile().exists())
            {
                crlOutputPath.toFile().mkdirs();
            }
        }
        // if (testCase.getProfile() != null)
        // {
        // String profile = (String) testCase.getProfile().get(0);
        //
        // if ("CRL".equalsIgnoreCase(profile))
        // {
        // Path crlOutputPath = Paths.get(outputDirectoryName, testCaseId, "crls");
        //
        // if (!crlOutputPath.toFile().exists())
        // {
        // crlOutputPath.toFile().mkdirs();
        // }
        // }
        // }

        try
        {
            for (String crlId : crlIds)
            {
                MDC.put("CRL", crlId);
                logger.info("Exporting revocation list.");

                testCaseObjects.append(crlId);
                testCaseObjects.append(System.getProperty("line.separator"));

                byte[] rawCrl = objectCache.getRawCRL(crlId);

                if (rawCrl == null)
                {
                    Utils.logError("Revocation list has not been issued.");
                    ObjectCache.getInstance().addError("Revocation list '" + crlId + "' has not been issued.");
                    continue;
                }

                String filename = crlId + ".crl";
                String pemFilename = crlId + ".pem.crl";

                Path crlOutputPath = Paths.get(outputDirectoryName, testCaseId, "crls");

                if (!crlOutputPath.toFile().exists())
                {
                    crlOutputPath.toFile().mkdirs();
                }

                Files.write(Paths.get(outputDirectoryName, testCaseId, "crls", filename), rawCrl);
                Files.write(Paths.get(outputDirectoryName, testCaseId, "crls", pemFilename),
                            Utils.exportPEMCRL(rawCrl));

                logger.info("Successfully exported revocation list.");

            }
        }
        finally
        {
            MDC.remove("CRL");
        }

        // Output OCSP responses

        try
        {
            for (String ocspId : ocspIds)
            {
                MDC.put("OCSP", ocspId);
                logger.info("Exporting OCSP responses.");

                testCaseObjects.append(ocspId);
                testCaseObjects.append(System.getProperty("line.separator"));

                byte[] rawOCSPResponse = objectCache.getRawOcspResponse(ocspId);

                if (rawOCSPResponse == null)
                {
                    Utils.logError("OCSP Response has not been issued.");
                    ObjectCache.getInstance().addError("OCSP Response  '" + ocspId + "' has not been issued.");
                    continue;
                }

                String filename = ocspId + ".ocsp.der";

                Path ocspOutputPath = Paths.get(outputDirectoryName, testCaseId, "ocspResponses");

                if (!ocspOutputPath.toFile().exists())
                {
                    ocspOutputPath.toFile().mkdirs();
                }

                Files.write(Paths.get(outputDirectoryName, testCaseId, "ocspResponses", filename), rawOCSPResponse);
                logger.info("Successfully exported OCSP response.");
            }
        }
        finally
        {
            MDC.remove("OCSP");
        }



        logger.info("Creating report.");

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String reportFilename =
            configurationProperties.getProperties().getString(ConfigurationProperties.REPORT_TEMPLATE_FILENAME,
                                                              "testReport.txt");
        String testObjectName =
            configurationProperties.getProperties().getString(ConfigurationProperties.REPORT_TEST_OBJECT_NAME, "");
        String testObjectVersion =
            configurationProperties.getProperties().getString(ConfigurationProperties.REPORT_TEST_OBJECT_VERSION, "");

        File reportTemplate = new File(reportFilename);

        if (!reportTemplate.exists())
        {
            Utils.exitProgramm("Report template file '" + reportFilename + "' does not exist.");
        }

        if (!reportTemplate.canRead())
        {
            Utils.exitProgramm("Report template file '" + reportFilename + "' is not readable.");
        }

        String reportContent = Utils.readFileContent(reportFilename);

        String expectedResult =
            Utils.getTestCaseExpectedResult(testCase) == null ? "n/a" : Utils.getTestCaseExpectedResult(testCase);

        String severity = Utils.getTestCaseSeverity(testCase) == null ? "n/a" : Utils.getTestCaseSeverity(testCase);

        String testCasePurpose =
            Utils.getTestCasePurpose(testCase) == null ? "n/a" : Utils.getTestCasePurpose(testCase);

        reportContent = reportContent.replaceAll(Pattern.quote("${testcase.id}"), testCaseId);
        // reportContent = reportContent.replaceAll(Pattern.quote("${testcase.title}"), testCaseTitle);
        reportContent = reportContent.replaceAll(Pattern.quote("${testcase.purpose}"), testCasePurpose);
        reportContent = reportContent.replaceAll(Pattern.quote("${testcase.expectedResult}"), expectedResult);
        reportContent = reportContent.replaceAll(Pattern.quote("${testcase.severity}"), severity);
        reportContent = reportContent.replaceAll(Pattern.quote("${report.testobject.name}"), testObjectName);
        reportContent = reportContent.replaceAll(Pattern.quote("${report.testobject.version}"), testObjectVersion);
        reportContent = reportContent.replaceAll(Pattern.quote("${testcase.data}"), testCaseObjects.toString());

        Files.write(Paths.get(outputDirectoryName, testCaseId, "testReport.txt"), reportContent.getBytes());

        logger.info("Successfully created report.");

    }
}
