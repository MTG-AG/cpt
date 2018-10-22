
package de.mtg.certpathtest.testcase.handlers;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.StringTokenizer;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.TestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PathExportHandler extends TestCaseHandler
{

    private static Logger logger = LoggerFactory.getLogger(PathExportHandler.class);

    private TestCase testCase;

    private static final String PATHS_SUBDIR_NAME = "paths";
    private static final String ISSUED_BY_LIST_FILENAME = "issuedByList.txt";
    private static final String ISSUED_TO_LIST_FILENAME = "issuedToList.txt";

    private static final String ISSUED_BY_DIRECTION = "issuedBy.pem";
    private static final String ISSUED_BY_DIRECTION_WITHOUT_TC = "issuedByNoTC.pem";
    private static final String ISSUED_BY_DIRECTION_WITHOUT_TA = "issuedByNoTA.pem";
    private static final String ISSUED_BY_DIRECTION_WITHOUT_BOTH = "issuedByNoTANoTC.pem";

    private static final String ISSUED_TO_DIRECTION = "issuedTo.pem";
    private static final String ISSUED_TO_DIRECTION_WITHOUT_TC = "issuedToNoTC.pem";
    private static final String ISSUED_TO_DIRECTION_WITHOUT_TA = "issuedToNoTA.pem";
    private static final String ISSUED_TO_DIRECTION_WITHOUT_BOTH = "issuedToNoTANoTC.pem";

    public PathExportHandler(TestCase testCase)
    {
        super(testCase);
        this.testCase = testCase;
    }

    public void execute() throws IOException, JAXBException
    {
        String testCaseId = testCase.getId();
        ObjectCache objectCache = ObjectCache.getInstance();

        String taId = Utils.getTrustAnchorCertificateID(objectCache.getPKIobjectsFromTestCase(testCaseId));
        String tcId = Utils.getTargetCertificateCertificateID(objectCache.getPKIobjectsFromTestCase(testCaseId));

        String outputDirectoryName =
                ConfigurationProperties.getInstance().getProperties()
                        .getString(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY);

        Path path = Paths.get(outputDirectoryName, testCaseId);

        if (!path.toFile().exists())
        {
            path.toFile().mkdirs();
        }

        Path pathsOutputPath = Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME);

        if (!pathsOutputPath.toFile().exists())
        {
            pathsOutputPath.toFile().mkdirs();
        }

        // Two cases: Either an explicit path is declared in the PKIObjects (the path MUST be created for whatever
        // reason) or the number of certificates in the intended path, as this specified in the PKI objects, matches
        // the total number of certificates. (There are test cases where it is necessary for the library to check
        // that the correct patch is constructed).

        PKIObjects pkiObjects = objectCache.getPKIobjectsFromTestCase(testCaseId);

        if (Utils.hasExplicitPath(pkiObjects))
        {

            de.mtg.certpathtest.pkiobjects.Path pkiObjectsPath = pkiObjects.getPath();
            String pathValue = pkiObjectsPath.getValue();
            StringTokenizer tokenizer = new StringTokenizer(pathValue, ",");

            ArrayList<String> issuedBy = new ArrayList<>();
            ArrayList<String> issuedTo = new ArrayList<>();
            while (tokenizer.hasMoreTokens())
            {
                String id = tokenizer.nextToken().trim();
                issuedBy.add(id);
                issuedTo.add(id);
            }
            Collections.reverse(issuedTo);
            writePaths(issuedBy, issuedTo, testCaseId, taId, tcId, -1, outputDirectoryName);
        }
        else
        {
            int size = Utils.getNumberOfCertificates(pkiObjects);
            ArrayList<String> issuedBy = Utils.sortCertificatesFromTAToTC(pkiObjects);
            ArrayList<String> issuedTo = Utils.sortCertificatesFromTCToTA(pkiObjects);
            writePaths(issuedBy, issuedTo, testCaseId, taId, tcId, size, outputDirectoryName);
        }
    }

    private void writePaths(ArrayList<String> issuedBy, ArrayList<String> issuedTo, String testCaseId, String taId,
                            String tcId, int size, String outputDirectoryName) throws IOException
    {
        StringBuilder issuedByStringBuilder = new StringBuilder();
        StringBuilder issuedToStringBuilder = new StringBuilder();

        if ((issuedBy.size() == issuedTo.size() && size == issuedBy.size()) || size == -1)
        {

            for (String id : issuedBy)
            {
                issuedByStringBuilder.append(id);
                if (id.equalsIgnoreCase(taId))
                {
                    issuedByStringBuilder.append(OutputHandler.TRUST_ANCHOR_FILE_ENDING);
                }
                else if (id.equalsIgnoreCase(tcId))
                {
                    issuedByStringBuilder.append(OutputHandler.TARGET_CERTIFICATE_FILE_ENDING);
                }
                else
                {
                    issuedByStringBuilder.append(OutputHandler.CA_CERTIFICATE_FILE_ENDING);
                }
                issuedByStringBuilder.append(System.getProperty("line.separator"));
            }

            for (String id : issuedTo)
            {
                issuedToStringBuilder.append(id);
                if (id.equalsIgnoreCase(taId))
                {
                    issuedToStringBuilder.append(OutputHandler.TRUST_ANCHOR_FILE_ENDING);
                }
                else if (id.equalsIgnoreCase(tcId))
                {
                    issuedToStringBuilder.append(OutputHandler.TARGET_CERTIFICATE_FILE_ENDING);
                }
                else
                {
                    issuedToStringBuilder.append(OutputHandler.CA_CERTIFICATE_FILE_ENDING);
                }
                issuedToStringBuilder.append(System.getProperty("line.separator"));
            }

            Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME, ISSUED_BY_LIST_FILENAME),
                        issuedByStringBuilder.toString().getBytes());
            Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME, ISSUED_TO_LIST_FILENAME),
                        issuedToStringBuilder.toString().getBytes());

            // Write PEM paths even if the number of certificates in the test case do not match

            String content = null;

            // issuedBy
            content = getContent(issuedBy, false, false);
            Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME, ISSUED_BY_DIRECTION),
                        content.getBytes());
            //
            // // issuedBy excluding TC
            // content = getContent(issuedBy, false, true);
            // Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME,
            // ISSUED_BY_DIRECTION_WITHOUT_TC),
            // content.getBytes());
            //
            // // issuedBy excluding TA
            // content = getContent(issuedBy, true, false);
            // Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME,
            // ISSUED_BY_DIRECTION_WITHOUT_TA),
            // content.getBytes());
            //
            // // issuedBy excluding TA/TC
            // content = getContent(issuedBy, true, true);
            // Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME,
            // ISSUED_BY_DIRECTION_WITHOUT_BOTH),
            // content.getBytes());

            // issuedTo
            content = getContent(issuedTo, false, false);
            Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME, ISSUED_TO_DIRECTION),
                        content.getBytes());
            //
            // // issuedTo excluding TC
            // content = getContent(issuedTo, true, false);
            // Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME,
            // ISSUED_TO_DIRECTION_WITHOUT_TC),
            // content.getBytes());
            //

            // issuedTo excluding TA (needed by e.g. OpenVPN)
            content = getContent(issuedTo, false, true);
            Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME, ISSUED_TO_DIRECTION_WITHOUT_TA),
                    content.getBytes());
            //
            // // issuedTo excluding TC/TA
            // content = getContent(issuedTo, true, true);
            // Files.write(Paths.get(outputDirectoryName, testCaseId, PATHS_SUBDIR_NAME,
            // ISSUED_TO_DIRECTION_WITHOUT_BOTH),
            // content.getBytes());
        }
    }

    private static String getContent(ArrayList<String> certificates, boolean excludeFirst, boolean excludeLast)
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        StringBuilder pemPathStringBuilder = new StringBuilder();

        int listSize = certificates.size();

        for (int i = 0; i < listSize; i++)
        {

            if (i == 0 & excludeFirst)
            {
                continue;
            }

            if (i == listSize - 1 & excludeLast)
            {
                continue;
            }

            String id = certificates.get(i);
            byte[] rawCertificate = objectCache.getRawCertificate(id);
            String pemEncoded = Utils.encodeCertificatePEM(rawCertificate);
            pemPathStringBuilder.append(pemEncoded);
            pemPathStringBuilder.append(System.getProperty("line.separator"));
        }

        return pemPathStringBuilder.toString();

    }
}
