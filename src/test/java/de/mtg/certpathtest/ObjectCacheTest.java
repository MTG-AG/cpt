
package de.mtg.certpathtest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.tr03124.Hypertext;
import de.mtg.tr03124.TestCase;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.ObjectCache}.
 *
 * @see de.mtg.certpathtest.ObjectCache ObjectCache
 *
 *
 */
public class ObjectCacheTest
{

    private ObjectCache cache = ObjectCache.getInstance();

    private KeyPair keyPair;

    private Certificate certificate;

    private TestCase testCase;

    private CRL crl;

    private String testCaseId;

    private String certId;

    private String crlId;

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024, new SecureRandom());
        keyPair = kpg.generateKeyPair();

        certId = "Cert_ID_001";
        crlId = "CRL_ID_001";
        testCaseId = "TestCase_ID_001";

        certificate = new Certificate();
        certificate.setId(certId);

        crl = new CRL();
        crl.setId(crlId);

        testCase = new TestCase();
        testCase.setTitle("TestCase");
        testCase.setId(testCaseId);
        testCase.setVersion("1.0");
        testCase.getProfile().add("Profile");
        Hypertext purpose = new Hypertext();
        purpose.getContent().add("Content");
        testCase.setPurpose(purpose);

    }

    /**
     *
     * Tests the basic behaviour of the class under test.
     *
     * @throws DuplicateKeyException if a PKI object with the same id is added more than once.
     * @throws InvalidKeySpecException if a public key could not be decoded.
     * @throws NoSuchAlgorithmException if the algorithm to decode the public key is unknowm.
     *
     */
    @Test
    public void test() throws DuplicateKeyException, NoSuchAlgorithmException, InvalidKeySpecException
    {

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        cache.addCertificate(certificate);
        cache.addCRL(crl);
        cache.addTestCase(testCase, testCaseId);

        cache.addPrivateKey(certId, privateKey);
        cache.addPrivateKey(certId + "_0001", privateKey);

        cache.addPublicKey(certId, publicKey.getEncoded());
        cache.addPublicKey(certId + "_0001", publicKey.getEncoded());
        cache.addPublicKey(certId + "_0002", publicKey.getEncoded());

        // just put any byte[] it does not have to be a real CRL
        cache.addCRL(crlId, publicKey.getEncoded());
        cache.addCRL(crlId + "_0001", publicKey.getEncoded());
        cache.addCRL(crlId + "_0002", publicKey.getEncoded());
        cache.addCRL(crlId + "_0003", publicKey.getEncoded());

        // just put any byte[] it does not have to be a real certificate
        cache.addCertificate(certId, publicKey.getEncoded());
        cache.addCertificate(certId + "_0001", publicKey.getEncoded());
        cache.addCertificate(certId + "_0002", publicKey.getEncoded());
        cache.addCertificate(certId + "_0003", publicKey.getEncoded());
        cache.addCertificate(certId + "_0004", publicKey.getEncoded());

        Assert.assertNotNull(cache.getCertificate(certId));
        Assert.assertNotNull(cache.getCRL(crlId));
        Assert.assertNotNull(cache.getTestCase(testCaseId));
        Assert.assertNotNull(cache.getPrivateKey(certId));
        Assert.assertNotNull(cache.getPublicKey((certId + "_0001")));
        Assert.assertNotNull(cache.getRawCertificate(certId));
        Assert.assertNotNull(cache.getRawCertificate(certId + "_0003"));
        Assert.assertNotNull(cache.getRawCRL(crlId));
        Assert.assertNotNull(cache.getRawCRL(crlId + "_0002"));

        Assert.assertEquals(certId, cache.getCertificate(certId).getId());
        Assert.assertEquals(crlId, cache.getCRL(crlId).getId());
        Assert.assertEquals(testCaseId, cache.getTestCase(testCaseId).getId());
        Assert.assertEquals(((RSAPrivateKey) privateKey).getModulus(),
                            ((RSAPrivateKey) cache.getPrivateKey(certId)).getModulus());

        byte[] encodedPublicKey = cache.getPublicKey(certId + "_0001");
        RSAPublicKey pubKey =
            (RSAPublicKey) de.mtg.security.asn1.x509.util.Util.buildPublicKey("RSA", encodedPublicKey);

        Assert.assertEquals(((RSAPublicKey) publicKey).getModulus(), pubKey.getModulus());
        Assert.assertTrue(Arrays.equals(publicKey.getEncoded(), cache.getRawCertificate(certId)));
        Assert.assertTrue(Arrays.equals(publicKey.getEncoded(), cache.getRawCertificate(certId + "_0003")));
        Assert.assertTrue(Arrays.equals(publicKey.getEncoded(), cache.getRawCRL(crlId)));
        Assert.assertTrue(Arrays.equals(publicKey.getEncoded(), cache.getRawCRL(crlId + "_0002")));

    }

    /**
     *
     * Tests whether the proper exception is thrown when a certificate with the same id is added twice.
     *
     * @throws DuplicateKeyException if a certificate with the same id is added more than once.
     *
     */
    @Test(expected = DuplicateKeyException.class)
    public void testDuplicateCertificate() throws DuplicateKeyException
    {

        cache.clear();
        cache.addCertificate(certificate);
        cache.addCertificate(certificate);
    }

    /**
     *
     * Tests whether the cache is properly cleared.
     *
     * @throws DuplicateKeyException if a PKI object with the same id is added more than once.
     */
    public void testClear() throws DuplicateKeyException
    {

        cache.clear();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        cache.addCertificate(certificate);
        cache.addCRL(crl);
        cache.addTestCase(testCase, testCaseId);
        cache.addPrivateKey(certId, privateKey);
        cache.addPublicKey(certId, publicKey.getEncoded());
        cache.addCRL(crlId, publicKey.getEncoded());
        cache.addCertificate(certId, publicKey.getEncoded());

        cache.clear();

        try
        {
            cache.addCertificate(certificate);
            cache.addCRL(crl);
            cache.addTestCase(testCase, testCaseId);
            cache.addPrivateKey(certId, privateKey);
            cache.addPublicKey(certId, publicKey.getEncoded());
            cache.addCRL(crlId, publicKey.getEncoded());
            cache.addCertificate(certId, publicKey.getEncoded());
        }
        catch (DuplicateKeyException dke)
        {
            Assert.fail("An exception should not have been thrown here because the cache has been cleared.");
        }
    }

    /**
     *
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @After
    public void tearDown() throws Exception
    {

    }
}
