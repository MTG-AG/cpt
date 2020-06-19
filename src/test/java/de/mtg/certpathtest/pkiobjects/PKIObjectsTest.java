
package de.mtg.certpathtest.pkiobjects;

import java.util.Random;

import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.tr03124.TestCase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.PKIObjects}.
 *
 * @see de.mtg.certpathtest.pkiobjects.PKIObjects PKIObjects
 */
public class PKIObjectsTest
{

    /**
     * Tests the basic functionality of {@link de.mtg.certpathtest.pkiobjects.PKIObjects}.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber("1234567678");
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        PKIObjects pkiObjects = new PKIObjects();
        pkiObjects.getCertificates().add(xmlCertificate);

        String testCaseId = "TESTCASE-0001";
        TestCase testCase = new TestCase();
        testCase.setId(testCaseId);

        objectCache.addPKIobjectsToTestCase(testCaseId, pkiObjects);

        Assertions.assertFalse(Utils.hasReference(testCase));

        xmlCertificate = new Certificate();
        xmlCertificate.setRefid(id);

        PKIObjects pkiObjectsWithReference = new PKIObjects();
        pkiObjectsWithReference.getCertificates().add(xmlCertificate);

        testCaseId = "TESTCASE-0002";
        testCase = new TestCase();
        testCase.setId(testCaseId);
        objectCache.addPKIobjectsToTestCase(testCaseId, pkiObjectsWithReference);

        Assertions.assertTrue(Utils.hasReference(testCase));

        objectCache.clear();

    }

    /**
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @AfterEach
    public void tearDown()
    {
        ObjectCache.getInstance().clear();
    }
}
