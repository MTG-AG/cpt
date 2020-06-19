
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.Modification;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import de.mtg.certpathtest.pkiobjects.SubjectDN;
import de.mtg.security.asn1.x509.cert.SimpleCertificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Units tests for the a {@Link TestToolCertificate} that has modifications.
 */
public class TestToolCertificateWithModificationTest
{

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the correct functionality of the <code>WRONG_SIGNATURE</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testWrongSignature() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
                        new String(Base64.encode(certificateCreator.getRootCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getRootCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        Certificate xmlCertificateWithModification = new Certificate();

        id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);
        xmlCertificateWithModification.setId(id);
        xmlCertificateWithModification.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificateWithModification.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificateWithModification.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificateWithModification.setVersion("2");
        xmlCertificateWithModification.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificateWithModification.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificateWithModification.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificateWithModification.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificateWithModification.setVerifiedBy(id);
        xmlCertificateWithModification.setModification(new Modification(
                        de.mtg.certpathtest.Modification.WRONG_SIGNATURE.name()));

        TestToolCertificate technicalCertificateWithMod = new TestToolCertificate(xmlCertificateWithModification);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509CertificateReference = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        bais = new ByteArrayInputStream(technicalCertificateWithMod.getEncoded());
        X509Certificate x509ModifiedCertificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        Assertions.assertTrue(!Arrays.equals(x509CertificateReference.getSignature(),
                                             x509ModifiedCertificate.getSignature()));

        //        Assertions.assertTrue(Arrays.equals(x509CertificateReference.getTBSCertificate(),
        //                                        x509ModifiedCertificate.getTBSCertificate()));

        x509CertificateReference.verify(certificateCreator.getRootCACertificate().getPublicKey());

        try
        {
            x509ModifiedCertificate.verify(certificateCreator.getRootCACertificate().getPublicKey());
            Assertions.fail("An exception should not have been thrown here because the signature of this certificate is wrong.");
        }
        catch (Exception e)
        {
            if (!(e instanceof SignatureException))
            {
                Assertions.fail(String.format("Expecting Signature Exception but got another one: '%s'.", e.getClass().getName()));
            }
        }

        ObjectCache.getInstance().clear();

    }

    /**
     * Tests the correct functionality of the <code>DUPLICATE_EXTENSION</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testDuplicateExtension() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
                        new String(Base64.encode(certificateCreator.getRootCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getRootCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);
        xmlCertificate.setModification(new Modification(de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.name()));

        Extension firstExtension = new Extension("digitalSignature", "2.5.29.15", "true", "Key Usage", "pretty");
        Extension secondExtension = new Extension("keyEncipherment", "2.5.29.15", "true", "Key Usage", "pretty");

        xmlCertificate.getExtensions().add(firstExtension);
        xmlCertificate.getExtensions().add(secondExtension);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Assertions.assertThrows(CertificateParsingException.class, () -> cf.generateCertificate(bais));

        bais.close();
        ObjectCache.getInstance().clear();

    }

    /**
     * Tests the correct functionality of the <code>EMPTY_SIGNATURE</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testEmptySignature() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
                        new String(Base64.encode(certificateCreator.getRootCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getRootCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);
        xmlCertificate.setModification(new Modification(de.mtg.certpathtest.Modification.EMPTY_SIGNATURE.name()));

        Extension ex1 = new Extension("digitalSignature", "2.5.29.15", "true", "Key Usage", "pretty");

        xmlCertificate.getExtensions().add(ex1);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        SimpleCertificate simpleCertificate = SimpleCertificate.getInstance(technicalCertificate.getEncoded());

        if (simpleCertificate.getSignature() != null)
        {
            Assertions.fail("This certificate should not have a signature.");
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Assertions.assertThrows(CertificateException.class, () -> cf.generateCertificate(bais));

        bais.close();
        ObjectCache.getInstance().clear();
    }

    /**
     * Tests the correct functionality of the <code>DIFF_SIGN_ALGORITHMS</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testDiffSignAlgorithms() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
                        new String(Base64.encode(certificateCreator.getRootCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getRootCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);
        xmlCertificate.setModification(new Modification(de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.name()));

        Extension ex1 = new Extension("digitalSignature", "2.5.29.15", "true", "Key Usage", "pretty");

        xmlCertificate.getExtensions().add(ex1);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        SimpleCertificate simpleCertificate = SimpleCertificate.getInstance(technicalCertificate.getEncoded());

        Assertions.assertTrue(!(simpleCertificate.getSigAlgOID().equals(simpleCertificate.getTbsCertificate().getSignature()
                                                                                         .getAlgorithm().getId())));

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Assertions.assertThrows(CertificateException.class, () -> cf.generateCertificate(bais));

        ObjectCache.getInstance().clear();

    }

    /**
     * Tests the correct functionality of the <code>RSA_LOW_EXPONENT</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testRSALowExponent() throws Exception
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);
        xmlCertificate.setModification(new Modification(de.mtg.certpathtest.Modification.RSA_LOW_EXPONENT.name()));

        objectCache.addCertificate(xmlCertificate);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        Assertions.assertEquals(3, ((RSAPublicKey) x509Certificate.getPublicKey()).getPublicExponent().intValue());

        Certificate issuedXmlCertificate = new Certificate();

        String newId = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        issuedXmlCertificate.setId(newId);
        issuedXmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        issuedXmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        issuedXmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        issuedXmlCertificate.setVersion("2");
        issuedXmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        issuedXmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        issuedXmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        issuedXmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        issuedXmlCertificate.setVerifiedBy(id);

        TestToolCertificate issuedTechnicalCertificate = new TestToolCertificate(issuedXmlCertificate);

        bais = new ByteArrayInputStream(issuedTechnicalCertificate.getEncoded());
        X509Certificate issuedx509Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        Assertions.assertThrows(SignatureException.class, () -> issuedx509Certificate.verify(x509Certificate.getPublicKey()));

        ObjectCache.getInstance().clear();

    }

    /**
     * Tests the correct functionality of the <code>WRONG_DER_ENCODING</code> modification.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testWrongDEREncoding() throws Exception
    {

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("ECDSA,prime192v1", "pretty"));
        xmlCertificate.setSignature("1.2.840.10045.4.3.2"); // SHA256WithECDSA
        xmlCertificate.setVerifiedBy(id);
        xmlCertificate.setModification(new Modification(de.mtg.certpathtest.Modification.WRONG_DER_ENCODING.name()));

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Assertions.assertThrows(CertificateException.class, () -> cf.generateCertificate(bais));

        bais.close();
        ObjectCache.getInstance().clear();

    }

}
