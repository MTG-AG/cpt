
package de.mtg.certpathtest.readers;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.DuplicateKeyException;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.ActionStep;
import de.mtg.tr03124.TestCase;

public class ExtractDataReader extends SimpleFileVisitor<Path>
{

    private static Logger logger = LoggerFactory.getLogger(ExtractDataReader.class);

    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes basicFileAttributes) throws IOException
    {

        // Steps:
        // 01. Put each test case in cache.
        // 02. Assign PKI Objects to a test case.
        // 03. Put (XML) Certificates in cache.
        // 04. Put (XML) CRLs in cache.
        // 05. Assign certificate ids to test case and vice versa.
        // 06. Assign CRL ids to test case and vice versa.

        Path name = file.getFileName();
        PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher("glob:*.{xml}");

        if (name != null && pathMatcher.matches(name))
        {

            // Step 01: Put each test case in cache.
            String filename = file.toFile().getName();

            MDC.put("TESTCASE", filename);

            logger.info("Reading test case from file.");

            TestCase testCase = Utils.extractTestCase(file.toFile());

            String testCaseId = Utils.getTestCaseId(testCase);

            String testCaseProfile = Utils.getTestCaseProfile(testCase);

            ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

            String[] profilesToRun =
                configurationProperties.getProperties().getStringArray(ConfigurationProperties.PROFILES_TO_RUN);
            String[] skipTestCases =
                configurationProperties.getProperties().getStringArray(ConfigurationProperties.SKIP_TEST_CASES);

            boolean skipTest = true;

            for (String profileToRun : profilesToRun)
            {
                if (testCaseProfile.equalsIgnoreCase(profileToRun))
                {
                    skipTest = false;
                }
            }

            if (skipTest)
            {
                logger.info("Skipping test case with id '{}' contained in file '{}', because it has profile '{}'. Test cases of this profile are not executed because this is the current configuration.",
                            testCaseId, filename, testCaseProfile);
            }

            if (!skipTest)
            {
                for (String skipTestCase : skipTestCases)
                {
                    if (skipTestCase.equalsIgnoreCase(testCaseId))
                    {
                        skipTest = true;
                    }
                }
                if (skipTest)
                {
                    logger.info("Skipping test case with id '{}' contained in file '{}' because this is the current configuration.",
                                testCaseId, filename);
                }
            }

            if (!skipTest)
            {

                if (testCase.getTestStep() == null)
                {
                    Utils.exitProgramm("Wrong TestCase definition. Error in TestStep element. Either none is specified or duplicates exist.");
                }
                if (testCase.getTestStep().get(0) == null)
                {
                    Utils.exitProgramm("Wrong TestCase definition. Error in TestStep.");
                }
                if (testCase.getTestStep().get(0).getSeverity() == null)
                {
                    Utils.exitProgramm("Wrong TestCase definition. Error in Severity element. Either none is specified or duplicates exist.");
                }

                if (!(testCase.getTestStep() != null && testCase.getTestStep().get(0) != null
                    && testCase.getTestStep().get(0).getExpectedResult() != null
                    && testCase.getTestStep().get(0).getExpectedResult().get(0) != null
                    && testCase.getTestStep().get(0).getExpectedResult().get(0).getText() != null
                    && testCase.getTestStep().get(0).getExpectedResult().get(0).getText().getContent() != null
                    && testCase.getTestStep().get(0).getExpectedResult().get(0).getText().getContent().get(0) != null))
                {
                    Utils.exitProgramm("Wrong TestCase definition. Expected Result has not been specified.");
                }

                if (testCaseId == null)
                {

                    Utils.exitProgramm("TestCase specified in file '{" + filename
                        + "}' has an empty id. The id of a test case must be present and not empty. Please correct this.");
                }

                logger.info("Successfully read test case with id '{}' from file '{}'.", testCaseId, filename);

                ObjectCache objectCache = ObjectCache.getInstance();

                try
                {
                    objectCache.addTestCase(testCase, testCaseId);
                }
                catch (DuplicateKeyException e)
                {
                    Utils.exitProgramm("TestCase with the same id '" + testCaseId
                        + "' already exists. The id of a test case must be unique. Please correct this.");
                }

                // Step 02: Assign PKI Objects to a test case.
                List<ActionStep> actionSteps = testCase.getTestStep();

                String pkiObjectsFilenameReference = null;

                if (actionSteps != null)
                {
                    for (ActionStep actionStep : actionSteps)
                    {
                        List<String> filenames = actionStep.getTestDataReference();
                        for (String pkiObjectsFilename : filenames)
                        {
                            pkiObjectsFilenameReference = pkiObjectsFilename;

                            logger.info("Reading and parsing file '{}'.", pkiObjectsFilename);
                            PKIObjectsReader pkiObjectsReader = new PKIObjectsReader(pkiObjectsFilename);

                            String pkiObjectsPath = ConfigurationProperties.getInstance().getProperties()
                                                                           .getString(ConfigurationProperties.PKI_OBJECTS_INPUT_DIRECTORY,
                                                                                      "pkiObjects");

                            Files.walkFileTree(Paths.get(pkiObjectsPath), pkiObjectsReader);
                            PKIObjects pkiObjects = pkiObjectsReader.getPKIObjects();

                            if (pkiObjects != null)
                            {
                                logger.info("Successfully read and parsed file '{}'.", pkiObjectsFilename);

                                PKIObjects pkiObjectsToWorkOn = null;
                                try
                                {
                                    logger.info("Applying replacements on PKI Objects.");
                                    pkiObjectsToWorkOn = Utils.applyReplacementsOnPKIObjects(pkiObjects);
                                }
                                catch (JAXBException e)
                                {
                                    Utils.exitProgramm("Could not not apply replacements on PKI Objects. Unexpected behaviour may occur. Please correct the errors.");
                                }

                                logger.info("Successfully applied replacements on PKI Objects.");

                                objectCache.addPKIobjectsToTestCase(testCaseId, pkiObjectsToWorkOn);
                            }
                            else
                            {
                                Utils.logError("Error reading and/or parsing file '" + pkiObjectsFilename + "'.");
                            }

                        }
                    }
                }

                // Step 03. Put (XML) Certificates in cache.
                // Step 04. Put (XML) CRLs in cache.
                // Step 05. Assign certificate ids to test case and vice versa.
                // Step 06. Assign CRL ids to test case and vice versa.

                PKIObjects pkiObjects = objectCache.getPKIobjectsFromTestCase(testCaseId);

                if (pkiObjects == null)
                {
                    Utils.exitProgramm("No PKI Objects are specified for this test case.");
                }

                ArrayList<Certificate> certificates = pkiObjects.getCertificates();

                ArrayList<CRL> crls = pkiObjects.getCRLs();

                int certSize = certificates.size();
                int crlSize = crls.size();

                logger.info("File '{}' references {} certificate(s) and {} revocation list(s) from PKI Objects file '{}'.",
                            filename, certSize, crlSize, pkiObjectsFilenameReference);

                assignObjectsToTestCase(testCase, pkiObjects);

            }

        }
        else
        {
            logger.warn("Found file '{}' which does not have a '.xml' extension and is probably not an XML file. Ignoring it.",
                        name.toFile().getName());
        }

        MDC.remove("TESTCASE");
        return FileVisitResult.CONTINUE;
    }

    public static void assignObjectsToTestCase(TestCase testCase, PKIObjects pkiObjects) throws IOException
    {

        ObjectCache objectCache = ObjectCache.getInstance();
        String testCaseId = Utils.getTestCaseId(testCase);

        ArrayList<Certificate> certificates = pkiObjects.getCertificates();

        ArrayList<CRL> crls = pkiObjects.getCRLs();

        for (Certificate certificate : certificates)
        {

            String certificateId = Utils.getCertificateId(certificate);

            if (certificateId == null)
            {
                Utils.exitProgramm("Wrong certificate or certificate with an empty id found in test case with id '{"
                    + testCaseId + "}'. The id of a certificate must be present. Please correct this.");
            }

            try
            {
                objectCache.addCertificate(certificate);
            }
            catch (DuplicateKeyException e)
            {
                Utils.exitProgramm("Certificate with the same id '{" + certificate.getId()
                    + "}' already exists. The id of a certificate must be unique. Please correct this.");
            }

            // cert2testcase
            objectCache.assignCertificateIdToTestCase(testCase, certificate);

            // testcase2cert
            objectCache.assignTestCaseToCertificateId(certificate, testCase);
        }

        for (CRL crl : crls)
        {

            String crlId = Utils.getCRLId(crl);

            if (crlId == null)
            {

                Utils.exitProgramm("Wrong CRL or CRL with an empty id found in test case with id '{" + testCaseId
                    + "}'. The id of a CRL must be present. Please correct this.");
            }

            try
            {
                objectCache.addCRL(crl);
            }
            catch (DuplicateKeyException e)
            {

                Utils.exitProgramm("CRL with the same id '{" + crl.getId()
                    + "}' already exists. The id of a certificate must be unique. Please correct this.");
            }

            // crl2testcase
            objectCache.assignCRLIdToTestCase(testCase, crl);

            // testcase2crl
            objectCache.assignTestCaseToCRLId(crl, testCase);
        }
    }

    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes basicFileAttributes)
    {
        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult postVisitDirectory(Path dir, IOException ioe)
    {
        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path file, IOException ioe)
    {
        Utils.logError("Could not read file '" + file.toString() + "'.");
        return FileVisitResult.CONTINUE;
    }

}