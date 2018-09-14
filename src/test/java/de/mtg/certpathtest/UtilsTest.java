
package de.mtg.certpathtest;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.Modification;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import de.mtg.certpathtest.pkiobjects.SubjectDN;
import de.mtg.certpathtest.pkiobjects.Variable;
import junit.framework.Assert;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for {@link Utils}
 *
 * @see Utils Utils
 */
public class UtilsTest
{
    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {

    }

    /**
     * Tests the {@link Utils#convertBitString(String)} method.
     *
     * @see Utils#convertBitString(String) convertBitString
     */
    @Test
    public void testConvertBitString()
    {
        String test;

        test = "110";
        byte[] result = Utils.convertBitString(test);
        Assert.assertEquals(1, result.length);
        Assert.assertEquals(6, (int) result[0]);

        test = "0000001";
        result = Utils.convertBitString(test);
        Assert.assertEquals(1, result.length);
        Assert.assertEquals(1, (int) result[0]);

        test = "00000001";
        result = Utils.convertBitString(test);
        Assert.assertEquals(1, result.length);
        Assert.assertEquals(1, (int) result[0]);

        test = "10000001";
        result = Utils.convertBitString(test);
        Assert.assertEquals(1, result.length);
        Assert.assertEquals(-127, (int) result[0]);

        test = "110000001";
        result = Utils.convertBitString(test);
        Assert.assertEquals(result.length, 2);
        Assert.assertEquals(1, (int) result[0]);
        Assert.assertEquals(-127, (int) result[1]);

        test = "110101000001";
        result = Utils.convertBitString(test);
        Assert.assertEquals(result.length, 2);

        Assert.assertEquals(13, (int) result[0]);
        Assert.assertEquals(65, (int) result[1]);

        test = "1101101010100101010111001100";
        result = Utils.convertBitString(test);
        Assert.assertEquals(result.length, 4);

        Assert.assertEquals(13, (int) result[0]);
        Assert.assertEquals(-86, (int) result[1]);
        Assert.assertEquals(85, (int) result[2]);
        Assert.assertEquals(-52, (int) result[3]);

    }

    /**
     * Tests the {@link Utils#cloneCertificate(Certificate)} method.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @see Utils#cloneCertificate(Certificate) cloneCertificate
     */
    @Test
    public void testCloneCertificate() throws JAXBException, IOException
    {

        Certificate certificate = new Certificate();
        certificate.setId("JUnit-0001");
        certificate.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        certificate.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));

        Utils.cloneCertificate(certificate);

    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method for the simple case in which a
     * certificate references a complete certificate directly.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCertificateOneLevel() throws JAXBException, IOException, DuplicateKeyException
    {

        String levelZeroId = "JUnit-Level0";
        Certificate levelZero = new Certificate();
        levelZero.setId(levelZeroId);
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));
        levelZero.setSerialNumber("123");
        levelZero.setSignature("1.2.3.4");
        levelZero.setNotBefore(new NotBefore("-2", "UTC"));
        levelZero.setNotAfter(new NotAfter("+2", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        levelZero.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addCertificate(levelZero);

        Certificate levelOne = new Certificate();
        levelOne.setId("JUnit-Level1");
        levelOne.setSerialNumber("1");
        levelOne.setVersion("300");
        levelOne.setRefid(levelZeroId);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelOne);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals("300", workCertificate.getVersion());
        Assert.assertEquals("1", workCertificate.getSerialNumber());
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals(levelZero.getNotBefore().getEncoding(), workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals(levelZero.getNotBefore().getValue(), workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());
        Assert.assertEquals(levelZero.getModification().getId(), workCertificate.getModification().getId());

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method for a complex case in which a
     * certificate references a certificate which references a complete certificate directly.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCertificateTwoLevels() throws JAXBException, IOException, DuplicateKeyException
    {

        String levelZeroId = "JUnit-Level0";
        String levelOneId = "JUnit-Level1";
        String levelTwoId = "JUnit-Level2";

        Certificate levelZero = new Certificate();
        levelZero.setId(levelZeroId);
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));
        levelZero.setSerialNumber("123");
        levelZero.setSignature("1.2.3.4");
        levelZero.setNotBefore(new NotBefore("-2", "UTC"));
        levelZero.setNotAfter(new NotAfter("+2", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        levelZero.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        ObjectCache objectCache = ObjectCache.getInstance();

        Certificate levelOne = new Certificate();
        levelOne.setId(levelOneId);
        levelOne.setSerialNumber("7");
        levelOne.setVersion("300");
        levelOne.setRefid(levelZeroId);

        Certificate levelTwo = new Certificate();
        levelTwo.setId(levelTwoId);
        levelTwo.setSerialNumber("478"); // overwrite serial number
        levelTwo.setRefid(levelOneId);

        objectCache.addCertificate(levelZero);
        objectCache.addCertificate(levelOne);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelTwo);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals("300", workCertificate.getVersion()); // from level 1
        Assert.assertEquals("478", workCertificate.getSerialNumber()); // from level 2
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals(levelZero.getNotBefore().getEncoding(), workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals(levelZero.getNotBefore().getValue(), workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());
        Assert.assertEquals(levelZero.getModification().getId(), workCertificate.getModification().getId());

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method for a complex case with
     * reference over three levels.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCertificateThreeLevels() throws JAXBException, IOException, DuplicateKeyException
    {

        String levelZeroId = "JUnit-Level0";
        String levelOneId = "JUnit-Level1";
        String levelTwoId = "JUnit-Level2";
        String levelThreeId = "JUnit-Level3";

        Certificate levelZero = new Certificate();
        levelZero.setId(levelZeroId);
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));
        levelZero.setSerialNumber("123");
        levelZero.setSignature("1.2.3.4");
        levelZero.setNotBefore(new NotBefore("-2", "UTC"));
        levelZero.setNotAfter(new NotAfter("+2", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        // levelZero.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        ObjectCache objectCache = ObjectCache.getInstance();

        Certificate levelOne = new Certificate();
        levelOne.setId(levelOneId);
        levelOne.setSerialNumber("7");
        levelOne.setVersion("300");
        levelOne.setRefid(levelZeroId);

        Certificate levelTwo = new Certificate();
        levelTwo.setId(levelTwoId);
        levelTwo.setSerialNumber("1024"); // overwrite serial number
        levelTwo.setNotBefore(new NotBefore("4", "GEN"));
        levelTwo.setRefid(levelOneId);

        Certificate levelThree = new Certificate();
        levelThree.setId(levelThreeId);
        levelThree.setSerialNumber("4096"); // overwrite serial number
        levelThree.setModification(new Modification(de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.name()));
        levelThree.setRefid(levelTwoId);

        objectCache.addCertificate(levelZero);
        objectCache.addCertificate(levelOne);
        objectCache.addCertificate(levelTwo);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelThree);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals("300", workCertificate.getVersion()); // from level 1
        Assert.assertEquals("4096", workCertificate.getSerialNumber()); // from level 2
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals("GEN", workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals("4", workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());
        Assert.assertEquals(de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.name(),
                            workCertificate.getModification().getId());

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method for a complex case with
     * reference over three levels and extensions.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCertificateThreeLevelsWithExtensions() throws JAXBException, IOException, DuplicateKeyException
    {

        String levelZeroId = "JUnit-Level0";
        String levelOneId = "JUnit-Level1";
        String levelTwoId = "JUnit-Level2";
        String levelThreeId = "JUnit-Level3";

        Certificate levelZero = new Certificate();
        levelZero.setId(levelZeroId);
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));
        levelZero.setSerialNumber("123");
        levelZero.setSignature("1.2.3.4");
        levelZero.setNotBefore(new NotBefore("-2", "UTC"));
        levelZero.setNotAfter(new NotAfter("+2", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));

        Extension firstExtension = new Extension("First Extension", "1.2.3.4.1", "true", "First Extension", "pretty");
        Extension secondExtension =
                new Extension("Second Extension", "1.2.3.4.2", "true", "Second Extension", "pretty");
        Extension thirdExtension = new Extension("Third Extension", "1.2.3.4.3", "true", "Third Extension", "pretty");
        Extension forthExtension = new Extension("Forth Extension", "1.2.3.4.4", "true", "Forth Extension", "pretty");
        ArrayList<Extension> extensions = new ArrayList<Extension>();
        extensions.add(firstExtension);
        extensions.add(secondExtension);
        extensions.add(thirdExtension);
        extensions.add(forthExtension);
        levelZero.setExtensions(extensions);

        // levelZero.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        ObjectCache objectCache = ObjectCache.getInstance();

        Certificate levelOne = new Certificate();
        levelOne.setId(levelOneId);
        levelOne.setSerialNumber("7");
        levelOne.setVersion("300");
        levelOne.setRefid(levelZeroId);

        Certificate levelTwo = new Certificate();
        levelTwo.setId(levelTwoId);
        levelTwo.setSerialNumber("1024"); // overwrite serial number
        levelTwo.setNotBefore(new NotBefore("4", "GEN"));
        levelTwo.setRefid(levelOneId);

        Certificate levelThree = new Certificate();
        levelThree.setId(levelThreeId);
        levelThree.setSerialNumber("4096"); // overwrite serial number
        levelThree.setModification(new Modification(de.mtg.certpathtest.Modification.WRONG_SIGNATURE.name()));
        levelThree.setRefid(levelTwoId);

        Extension updatedforthExtension =
                new Extension("Updated Forth Extension", "1.2.3.4.4", "true", "Updated Forth Extension", "pretty");
        ArrayList<Extension> updatedExtensions = new ArrayList<Extension>();
        updatedExtensions.add(updatedforthExtension);
        levelThree.setExtensions(updatedExtensions);

        objectCache.addCertificate(levelZero);
        objectCache.addCertificate(levelOne);
        objectCache.addCertificate(levelTwo);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelThree);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals("300", workCertificate.getVersion()); // from level 1
        Assert.assertEquals("4096", workCertificate.getSerialNumber()); // from level 2
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals("GEN", workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals("4", workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());
        Assert.assertEquals(de.mtg.certpathtest.Modification.WRONG_SIGNATURE.name(),
                            workCertificate.getModification().getId());
        Assert.assertEquals(4, workCertificate.getExtensions().size());

        HashMap<String, String> currentExtensions = new HashMap<String, String>();

        for (Extension extension : workCertificate.getExtensions())
        {
            currentExtensions.put(extension.getOid(), extension.getValue());
        }

        Assert.assertTrue(currentExtensions.containsKey("1.2.3.4.4"));
        Assert.assertEquals("Updated Forth Extension", currentExtensions.get(("1.2.3.4.4")));

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method for a complex case with
     * reference over three levels, extensions, and the DUPLICATE_EXTENSION modification.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCertificateThreeLevelsWithExtensionsAndModification()
            throws JAXBException, IOException, DuplicateKeyException
    {

        String levelZeroId = "JUnit-Level0";
        String levelOneId = "JUnit-Level1";
        String levelTwoId = "JUnit-Level2";
        String levelThreeId = "JUnit-Level3";

        Certificate levelZero = new Certificate();
        levelZero.setId(levelZeroId);
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=DE", "UTF8"));
        levelZero.setSerialNumber("123");
        levelZero.setSignature("1.2.3.4");
        levelZero.setNotBefore(new NotBefore("-2", "UTC"));
        levelZero.setNotAfter(new NotAfter("+2", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));

        Extension firstExtension = new Extension("First Extension", "1.2.3.4.1", "true", "First Extension", "pretty");
        Extension secondExtension =
                new Extension("Second Extension", "1.2.3.4.2", "true", "Second Extension", "pretty");
        Extension thirdExtension = new Extension("Third Extension", "1.2.3.4.3", "true", "Third Extension", "pretty");
        Extension forthExtension = new Extension("Forth Extension", "1.2.3.4.4", "true", "Forth Extension", "pretty");
        ArrayList<Extension> extensions = new ArrayList<Extension>();
        extensions.add(firstExtension);
        extensions.add(secondExtension);
        extensions.add(thirdExtension);
        extensions.add(forthExtension);
        levelZero.setExtensions(extensions);

        // levelZero.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        ObjectCache objectCache = ObjectCache.getInstance();

        Certificate levelOne = new Certificate();
        levelOne.setId(levelOneId);
        levelOne.setSerialNumber("7");
        levelOne.setVersion("300");
        levelOne.setRefid(levelZeroId);

        Certificate levelTwo = new Certificate();
        levelTwo.setId(levelTwoId);
        levelTwo.setSerialNumber("1024"); // overwrite serial number
        levelTwo.setNotBefore(new NotBefore("4", "GEN"));
        levelTwo.setRefid(levelOneId);

        Certificate levelThree = new Certificate();
        levelThree.setId(levelThreeId);
        levelThree.setSerialNumber("4096"); // overwrite serial number
        levelThree.setModification(new Modification(de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.name()));
        levelThree.setRefid(levelTwoId);

        Extension updatedforthExtension =
                new Extension("Updated Forth Extension", "1.2.3.4.4", "true", "Updated Forth Extension", "pretty");
        ArrayList<Extension> updatedExtensions = new ArrayList<Extension>();
        updatedExtensions.add(updatedforthExtension);
        levelThree.setExtensions(updatedExtensions);

        objectCache.addCertificate(levelZero);
        objectCache.addCertificate(levelOne);
        objectCache.addCertificate(levelTwo);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelThree);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals("300", workCertificate.getVersion()); // from level 1
        Assert.assertEquals("4096", workCertificate.getSerialNumber()); // from level 2
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals("GEN", workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals("4", workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());
        Assert.assertEquals(de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.name(),
                            workCertificate.getModification().getId());
        Assert.assertEquals(5, workCertificate.getExtensions().size());

        HashMap<String, String> currentExtensions = new HashMap<String, String>();

        for (Extension extension : workCertificate.getExtensions())
        {
            currentExtensions.put(extension.getValue(), extension.getOid());
        }

        Assert.assertTrue(currentExtensions.containsKey("Updated Forth Extension"));
        Assert.assertTrue(currentExtensions.containsKey("Forth Extension"));
        Assert.assertEquals("1.2.3.4.4", currentExtensions.get(("Updated Forth Extension")));
        Assert.assertEquals("1.2.3.4.4", currentExtensions.get(("Forth Extension")));

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#getDifferentAlgorithm(String)} method.
     *
     * @see Utils#getDifferentAlgorithm(String) getDifferentAlgorithm
     */
    @Test
    public void testGetDifferentAlgorithm()
    {

        String algorithmOID = "1.2.840.113549.1.1.11";

        Assert.assertNotSame(algorithmOID, Utils.getDifferentAlgorithm(algorithmOID));

    }

    /**
     * Tests the {@link Utils#createCompleteCertificateFromReference(Certificate)} method checking especially whether
     * the original certificate id remains intact.
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @throws DuplicateKeyException if a certificate from the tests is added twice in the cache.
     * @see Utils#createCompleteCertificateFromReference(Certificate) createCompleteCertificateFromReference
     */
    @Test
    public void copyCheckIds() throws JAXBException, IOException, DuplicateKeyException
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        String levelZeroId = "CERT_PATH_COMMON_01_EE";

        Certificate levelZero = new Certificate();
        levelZero.setType("TC");
        levelZero.setId(levelZeroId);
        levelZero.setVerifiedBy("CERT_PATH_COMMON_01_SUB_CA");
        levelZero.setVersion("2");
        levelZero.setIssuerDN(new IssuerDN("CN=Test Sub CA, C=DE", "UTF8"));
        levelZero.setSubjectDN(new SubjectDN("CN=Test EE, C=DE", "UTF8"));
        levelZero.setSerialNumber("1");
        levelZero.setSignature("1.2.840.113549.1.1.11");
        levelZero.setNotBefore(new NotBefore("-8H", "UTC"));
        levelZero.setNotAfter(new NotAfter("+1Y", "UTC"));
        levelZero.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        Extension akie = new Extension("", "2.5.29.35", "false", "Authority Key Identifier", "pretty");
        Extension skie = new Extension("", "2.5.29.14", "false", "Subject Key Identifier", "pretty");
        Extension keyUsage = new Extension("digitalSignature", "2.5.29.15", "true", "Key Usage", "pretty");
        Extension certificatePolicies = new Extension("1.2.3.4", "2.5.29.32", "true", "Certificate Policies", "pretty");
        Extension basicConstraints = new Extension("false", "2.5.29.19", "true", "Basic Constraints", "pretty");
        levelZero.getExtensions().add(akie);
        levelZero.getExtensions().add(skie);
        levelZero.getExtensions().add(keyUsage);
        levelZero.getExtensions().add(certificatePolicies);
        levelZero.getExtensions().add(basicConstraints);

        objectCache.addCertificate(levelZero);

        Certificate levelOne = new Certificate();
        levelOne.setOverwrite("true");
        levelOne.setType("TC");
        levelOne.setId("CERT_PATH_EMAIL_02_EE");
        levelOne.setRefid(levelZeroId);
        Extension extension = new Extension("1.3.6.1.5.5.7.3.4", "2.5.29.37", "false", "Extended Key Usage", "pretty");
        levelOne.getExtensions().add(extension);

        Certificate workCertificate = Utils.createCompleteCertificateFromReference(levelOne);

        Assert.assertEquals(levelZero.getVerifiedBy(), workCertificate.getVerifiedBy());
        Assert.assertEquals(6, workCertificate.getExtensions().size());
        Assert.assertEquals("1", workCertificate.getSerialNumber());
        Assert.assertEquals(levelZero.getSignature(), workCertificate.getSignature());
        Assert.assertEquals(levelZero.getIssuerDN().getEncoding(), workCertificate.getIssuerDN().getEncoding());
        Assert.assertEquals(levelZero.getIssuerDN().getValue(), workCertificate.getIssuerDN().getValue());
        Assert.assertEquals(levelZero.getSubjectDN().getEncoding(), workCertificate.getSubjectDN().getEncoding());
        Assert.assertEquals(levelZero.getSubjectDN().getValue(), workCertificate.getSubjectDN().getValue());
        Assert.assertEquals(levelZero.getNotBefore().getEncoding(), workCertificate.getNotBefore().getEncoding());
        Assert.assertEquals(levelZero.getNotBefore().getValue(), workCertificate.getNotBefore().getValue());
        Assert.assertEquals(levelZero.getNotAfter().getEncoding(), workCertificate.getNotAfter().getEncoding());
        Assert.assertEquals(levelZero.getNotAfter().getValue(), workCertificate.getNotAfter().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getValue(), workCertificate.getPublicKey().getValue());
        Assert.assertEquals(levelZero.getPublicKey().getType(), workCertificate.getPublicKey().getType());
        Assert.assertEquals(levelZero.getIssuerUniqueID(), workCertificate.getIssuerUniqueID());
        Assert.assertEquals(levelZero.getSubjectUniqueID(), workCertificate.getSubjectUniqueID());

        Assert.assertEquals("CERT_PATH_EMAIL_02_EE", workCertificate.getId());

        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the {@link Utils#applyReplacementsOnPKIObjects(PKIObjects)} method .
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @see Utils#applyReplacementsOnPKIObjects(PKIObjects) applyReplacementsOnPKIObjects
     */
    @Test
    public void testApplyReplacements() throws JAXBException, IOException
    {

        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("${issuerDN}", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber("${serialNumber}");
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("${publicKey}", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        PKIObjects pkiObjects = new PKIObjects();
        pkiObjects.getCertificates().add(xmlCertificate);

        ConfigurationProperties properties = ConfigurationProperties.getInstance();

        properties.getProperties();
        properties.addSimpleProperty("replace.publicKey", "RSA,2048");
        properties.addSimpleProperty("replace.issuerDN", "CN=Test Issuer, C=DE");
        properties.addSimpleProperty("replace.serialNumber", "12345678");
        Hashtable<String, String> replacementProperties = properties.getReplacementProperties();

        Assert.assertEquals("12345678", replacementProperties.get("replace.serialNumber"));
        Assert.assertEquals("CN=Test Issuer, C=DE", replacementProperties.get("replace.issuerDN"));
        Assert.assertEquals("RSA,2048", replacementProperties.get("replace.publicKey"));

        String newPkiObjects = Utils.applyReplacementsOnPKIObjects(pkiObjects).toString();

        Assert.assertTrue(newPkiObjects.indexOf("RSA,2048") != -1);
        Assert.assertTrue(newPkiObjects.indexOf("CN=Test Issuer, C=DE") != -1);
        Assert.assertTrue(newPkiObjects.indexOf("12345678") != -1);

    }


    /**
     * Tests the {@link Utils#applyVariableValuesOnPKIObjects(PKIObjects)} (PKIObjects)} method .
     *
     * @throws IOException if an exception during marshalling/unmarshalling XML occurs.
     * @throws JAXBException if an exception during marshalling/unmarshalling XML occurs.
     * @see Utils#applyVariableValuesOnPKIObjects(PKIObjects) applyVariableValuesOnPKIObjects
     */
    @Test
    public void testApplyVariableValuesOnPKIObjects() throws JAXBException, IOException
    {

        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("${issuerDN}", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber("${serialNumber}");
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("${publicKey}", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        String crlDistributionPointValue =
                "%rootCrldp%";
        xmlCertificate.getExtensions().add(new Extension(
                "%rootCrldp%",
                "2.5.29.31",
                "false",
                "CRL Distribution Points",
                "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                "%subCrldp%",
                "2.5.29.31",
                "false",
                "CRL Distribution Points",
                "pretty"));

        Variable firstVar = new Variable();
        firstVar.setName("rootCrldp");
        firstVar.setValue("https://root.crl");
        Variable secondVar = new Variable();
        secondVar.setName("subCrldp");
        secondVar.setValue("https://sub.crl");

        PKIObjects pkiObjects = new PKIObjects();
        pkiObjects.getCertificates().add(xmlCertificate);
        pkiObjects.getVariables().add(firstVar);
        pkiObjects.getVariables().add(secondVar);

        ConfigurationProperties properties = ConfigurationProperties.getInstance();

        properties.getProperties();
        properties.addSimpleProperty("replace.publicKey", "RSA,2048");
        properties.addSimpleProperty("replace.issuerDN", "CN=Test Issuer, C=DE");
        properties.addSimpleProperty("replace.serialNumber", "12345678");
        Hashtable<String, String> replacementProperties = properties.getReplacementProperties();

        Assert.assertEquals("12345678", replacementProperties.get("replace.serialNumber"));
        Assert.assertEquals("CN=Test Issuer, C=DE", replacementProperties.get("replace.issuerDN"));
        Assert.assertEquals("RSA,2048", replacementProperties.get("replace.publicKey"));

        pkiObjects = Utils.applyReplacementsOnPKIObjects(pkiObjects);

        PKIObjects newPkiObjects = Utils.applyVariableValuesOnPKIObjects(pkiObjects);

        Assert.assertTrue(newPkiObjects.toString().indexOf("RSA,2048") != -1);
        Assert.assertTrue(newPkiObjects.toString().indexOf("CN=Test Issuer, C=DE") != -1);
        Assert.assertTrue(newPkiObjects.toString().indexOf("12345678") != -1);
        Assert.assertTrue(newPkiObjects.toString().indexOf("https://root.crl") != -1);

        Pattern pattern = Pattern.compile(Pattern.quote("https://root.crl"));
        Matcher matcher = pattern.matcher(newPkiObjects.toString());
        int matchCounter = 0;
        while (matcher.find())
        {
            matchCounter++;
        }

        // once as a variable and once as a replaced value
        Assert.assertEquals(2, matchCounter);

        pattern = Pattern.compile(Pattern.quote("https://sub.crl"));
        matcher = pattern.matcher(newPkiObjects.toString());
        matchCounter = 0;
        while (matcher.find())
        {
            matchCounter++;
        }

        // once as a variable and once as a replaced value
        Assert.assertEquals(2, matchCounter);

    }

    /**
     * Tests the {@link Utils#createDummyCertificate(int)} method .
     *
     * @throws CertificateException if an exception occurs while creating the certificate.
     * @throws IOException if an exception occurs while creating the certificate.
     * @see Utils#createDummyCertificate(int) createDummyCertificate
     */
    @Test
    public void testCreateDummyCertificate() throws CertificateException, IOException
    {

        Random random = new Random();

        for (int i = 0; i < 100; i++)
        {

            int randomInteger = random.nextInt(65540);

            try
            {
                X509Certificate cert = Utils.createDummyCertificate(randomInteger);
                assertNotNull(cert);
                assertTrue(cert.getSerialNumber().compareTo(BigInteger.TEN) == 0);
                assertTrue(cert.getEncoded().length == randomInteger);
            }
            catch (IllegalArgumentException e)
            {
                if (randomInteger >= 281)
                {
                    fail("Should not have thrown illegal argument exception.");
                }

            }

        }

    }

    /**
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @After
    public void tearDown() throws Exception
    {
        ObjectCache.getInstance().clear();
    }
}
