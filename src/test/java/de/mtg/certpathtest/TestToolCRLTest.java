
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.NextUpdate;
import de.mtg.certpathtest.pkiobjects.RevocationDate;
import de.mtg.certpathtest.pkiobjects.RevokedCertificate;
import de.mtg.certpathtest.pkiobjects.ThisUpdate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * Units tests for the main functionality of {@Link TestToolCRL}.
 *
 */
public class TestToolCRLTest
{

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeAll
    public static void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     * Tests the creation of a simple CRL.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testBasic() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addPrivateKey(id, certificateCreator.getRootCAPrivateKey());

        CRL xmlCRL = new CRL();

        xmlCRL.setId(id);
        xmlCRL.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCRL.setVersion("1");
        xmlCRL.setThisUpdate(new ThisUpdate("-3D", "UTC"));
        xmlCRL.setNextUpdate(new NextUpdate("+3D", "UTC"));
        xmlCRL.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCRL.setVerifiedBy(id);

        TestToolCRL technicalCRL = new TestToolCRL(xmlCRL);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCRL.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL asn1CRL = (X509CRL) cf.generateCRL(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, asn1CRL.getThisUpdate());
        crlBuilder.setNextUpdate(asn1CRL.getNextUpdate());

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL highLevelCRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        Assertions.assertTrue(Arrays.equals(asn1CRL.getTBSCertList(), highLevelCRL.getTBSCertList()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getSignature(), highLevelCRL.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getEncoded(), highLevelCRL.getEncoded()));

        highLevelCRL.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1CRL.verify(certificateCreator.getRootCACertificate().getPublicKey());

        objectCache.clear();
    }

    /**
     *
     * Tests the creation of a simple CRL with a revoked certificate.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testBasicWithRevokedCertificate() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addPrivateKey(id, certificateCreator.getRootCAPrivateKey());
        objectCache.addCertificate(id, certificateCreator.getRootCACertificate().getEncoded());

        CRL xmlCRL = new CRL();

        xmlCRL.setId(id);
        xmlCRL.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCRL.setVersion("1");
        xmlCRL.setThisUpdate(new ThisUpdate("-3D", "UTC"));
        xmlCRL.setNextUpdate(new NextUpdate("+3D", "UTC"));
        xmlCRL.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCRL.setVerifiedBy(id);

        ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();

        RevokedCertificate revokedCertificate = new RevokedCertificate();
        revokedCertificate.setRefid(id);
        revokedCertificate.setRevocationDate(new RevocationDate("-3D", "UTC"));
        revokedCertificates.add(revokedCertificate);

        xmlCRL.setRevokedCertificates(revokedCertificates);

        TestToolCRL technicalCRL = new TestToolCRL(xmlCRL);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCRL.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL asn1CRL = (X509CRL) cf.generateCRL(bais);
        bais.close();

        X509CRLEntry revokedCertificateFromCRL =
            asn1CRL.getRevokedCertificate(certificateCreator.getRootCACertificate().getSerialNumber());

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, asn1CRL.getThisUpdate());
        crlBuilder.setNextUpdate(asn1CRL.getNextUpdate());

        crlBuilder.addCRLEntry(certificateCreator.getRootCACertificate().getSerialNumber(),
                               revokedCertificateFromCRL.getRevocationDate(), null);

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL highLevelCRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        Assertions.assertTrue(Arrays.equals(asn1CRL.getTBSCertList(), highLevelCRL.getTBSCertList()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getSignature(), highLevelCRL.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getEncoded(), highLevelCRL.getEncoded()));

        highLevelCRL.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1CRL.verify(certificateCreator.getRootCACertificate().getPublicKey());

        objectCache.clear();

    }

    /**
     *
     * Tests the creation of a simple CRL with a revoked certificate and a CRL containing extensions.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testBasicWithRevokedCertificateAndExtensions() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addPrivateKey(id, certificateCreator.getRootCAPrivateKey());
        objectCache.addCertificate(id, certificateCreator.getRootCACertificate().getEncoded());

        CRL xmlCRL = new CRL();

        xmlCRL.setId(id);
        xmlCRL.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCRL.setVersion("1");
        xmlCRL.setThisUpdate(new ThisUpdate("-3D", "UTC"));
        xmlCRL.setNextUpdate(new NextUpdate("+3D", "UTC"));
        xmlCRL.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCRL.setVerifiedBy(id);

        xmlCRL.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));

        ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();

        RevokedCertificate revokedCertificate = new RevokedCertificate();
        revokedCertificate.setRefid(id);
        revokedCertificate.setRevocationDate(new RevocationDate("-3D", "UTC"));
        revokedCertificates.add(revokedCertificate);

        xmlCRL.setRevokedCertificates(revokedCertificates);

        TestToolCRL technicalCRL = new TestToolCRL(xmlCRL);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCRL.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL asn1CRL = (X509CRL) cf.generateCRL(bais);
        bais.close();

        X509CRLEntry revokedCertificateFromCRL =
            asn1CRL.getRevokedCertificate(certificateCreator.getRootCACertificate().getSerialNumber());

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, asn1CRL.getThisUpdate());
        crlBuilder.setNextUpdate(asn1CRL.getNextUpdate());
        org.bouncycastle.asn1.x509.CRLNumber crlNumber = new CRLNumber(new BigInteger("1234"));

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, true, crlNumber);
        extensionsGenerator.generate().getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber);
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber));

        crlBuilder.addCRLEntry(certificateCreator.getRootCACertificate().getSerialNumber(),
                               revokedCertificateFromCRL.getRevocationDate(), null);

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL highLevelCRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        Assertions.assertTrue(Arrays.equals(asn1CRL.getTBSCertList(), highLevelCRL.getTBSCertList()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getSignature(), highLevelCRL.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getEncoded(), highLevelCRL.getEncoded()));

        highLevelCRL.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1CRL.verify(certificateCreator.getRootCACertificate().getPublicKey());

        objectCache.clear();

    }

    /**
     *
     * Tests the creation of a simple CRL with a revoked certificate, a CRL containing extensions and the revoked
     * certificate containing extensions.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testBasicWithRevokedCertificateAndExtensionsAndCRLEntryExtensions() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addPrivateKey(id, certificateCreator.getRootCAPrivateKey());
        objectCache.addCertificate(id, certificateCreator.getRootCACertificate().getEncoded());

        CRL xmlCRL = new CRL();

        xmlCRL.setId(id);
        xmlCRL.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCRL.setVersion("1");
        xmlCRL.setThisUpdate(new ThisUpdate("-3D", "UTC"));
        xmlCRL.setNextUpdate(new NextUpdate("+3D", "UTC"));
        xmlCRL.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCRL.setVerifiedBy(id);

        xmlCRL.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));

        ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();

        RevokedCertificate revokedCertificate = new RevokedCertificate();
        revokedCertificate.setRefid(id);
        revokedCertificate.setRevocationDate(new RevocationDate("-3D", "UTC"));
        revokedCertificate.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));
        revokedCertificates.add(revokedCertificate);

        xmlCRL.setRevokedCertificates(revokedCertificates);

        TestToolCRL technicalCRL = new TestToolCRL(xmlCRL);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCRL.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL asn1CRL = (X509CRL) cf.generateCRL(bais);
        bais.close();

        X509CRLEntry revokedCertificateFromCRL =
            asn1CRL.getRevokedCertificate(certificateCreator.getRootCACertificate().getSerialNumber());

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, asn1CRL.getThisUpdate());
        crlBuilder.setNextUpdate(asn1CRL.getNextUpdate());
        org.bouncycastle.asn1.x509.CRLNumber crlNumber = new CRLNumber(new BigInteger("1234"));

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, true, crlNumber);
        extensionsGenerator.generate().getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber);
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber));

        crlBuilder.addCRLEntry(certificateCreator.getRootCACertificate().getSerialNumber(),
                               revokedCertificateFromCRL.getRevocationDate(), extensionsGenerator.generate());

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL highLevelCRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        Assertions.assertTrue(Arrays.equals(asn1CRL.getTBSCertList(), highLevelCRL.getTBSCertList()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getSignature(), highLevelCRL.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getEncoded(), highLevelCRL.getEncoded()));

        highLevelCRL.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1CRL.verify(certificateCreator.getRootCACertificate().getPublicKey());

        objectCache.clear();

    }

    /**
     *
     * Tests the creation of a simple CRL with a revoked certificate, a CRL containing many extensions and the revoked
     * certificate containing also many extensions.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testManyExtensions() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        ObjectCache objectCache = ObjectCache.getInstance();

        objectCache.addPrivateKey(id, certificateCreator.getRootCAPrivateKey());
        objectCache.addCertificate(id, certificateCreator.getRootCACertificate().getEncoded());
        objectCache.addPublicKey(id, certificateCreator.getRootCACertificate().getPublicKey().getEncoded());

        CRL xmlCRL = new CRL();

        xmlCRL.setId(id);
        xmlCRL.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCRL.setVersion("1");
        xmlCRL.setThisUpdate(new ThisUpdate("-3D", "UTC"));
        xmlCRL.setNextUpdate(new NextUpdate("+3D", "UTC"));
        xmlCRL.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCRL.setVerifiedBy(id);

        ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();

        RevokedCertificate revokedCertificate = new RevokedCertificate();

        // start adding crl extensions

        String sanValue = "rfc822Name=a@a.de,dNSName=owneddn.de,iPAddress=127.0.0.1";
        String crlDistributionPointValue =
            "http://crl.url.de/crl.crl|ldap://ldap.url.de/cn=crl,dc=de?certificateRevocationList";

        xmlCRL.getExtensions().add(new Extension("", "2.5.29.35", "false", "AKI", "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "digitalSignature, keyEncipherment",
                                                     "2.5.29.15",
                                                     "true",
                                                     "Key Usage",
                                                     "pretty"));
        xmlCRL.getExtensions().add(new Extension("1.2.3.4.5", "2.5.29.32", "false", "Certificate Polices", "pretty"));
        xmlCRL.getExtensions().add(new Extension("true", "2.5.29.19", "true", "Basic Constraints", "pretty"));

        xmlCRL.getExtensions().add(new Extension(sanValue, "2.5.29.17", "false", "Subject Alternative Name", "pretty"));

        xmlCRL.getExtensions().add(new Extension(sanValue, "2.5.29.18", "false", "Issuer Alternative Name", "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "BBwwGjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB",
                                                     "2.5.29.9",
                                                     "false",
                                                     "Subject Directory Attibutes",
                                                     "raw"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "1.2,1.3.3.4|2.5.6.5.6,1.0.7.8",
                                                     "2.5.29.33",
                                                     "true",
                                                     "Policy Mappings",
                                                     "pretty"));
        xmlCRL.getExtensions().add(new Extension(
                                                 "permitted:dNSName=owneddn.de,excluded:rfc822Name=a@a.de",
                                                     "2.5.29.30",
                                                     "true",
                                                     "Name Constraints",
                                                     "pretty"));

        // xmlCRL.getExtensions().add(new Extension(
        // "requireExplicitPolicy=2,",
        // "2.5.29.36",
        // "false", // SUN requires false although this extension should be
        // // critical
        // "Policy Constraints",
        // "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
                                                     "2.5.29.37",
                                                     "false",
                                                     "Extended Key Usage",
                                                     "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 crlDistributionPointValue,
                                                     "2.5.29.31",
                                                     "false",
                                                     "CRL Distribution Points",
                                                     "pretty"));

        xmlCRL.getExtensions().add(new Extension("48", "2.5.29.54", "true", "Inhibit anyPolicy", "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 crlDistributionPointValue,
                                                     "2.5.29.46",
                                                     "false",
                                                     "Freshest CRL",
                                                     "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "https://ocsp.url.de/ocsp",
                                                     "1.3.6.1.5.5.7.1.1",
                                                     "false",
                                                     "Authority Information Access",
                                                     "pretty"));
        xmlCRL.getExtensions().add(new Extension(
                                                 "https://ca.url.de/repository",
                                                     "1.3.6.1.5.5.7.1.11",
                                                     "false",
                                                     "Subject Information Access",
                                                     "pretty"));

        xmlCRL.getExtensions().add(new Extension(
                                                 "http://crl.url.de/crl.crl",
                                                     "2.5.29.28",
                                                     "true",
                                                     "Issuing Distribution Point",
                                                     "pretty"));

        xmlCRL.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));

        xmlCRL.getExtensions().add(new Extension("28", "2.5.29.27", "true", "Delta CRL Indicator", "pretty"));

        xmlCRL.getExtensions().add(new Extension("3", "2.5.29.21", "true", "Reason Code", "pretty"));
        xmlCRL.getExtensions().add(new Extension("-2D,GEN", "2.5.29.24", "false", "Invalidity Date", "pretty"));
        xmlCRL.getExtensions().add(new Extension(
                                                 "CN=Test Issuer, C=DE|UTF8",
                                                     "2.5.29.29",
                                                     "false",
                                                     "Certificate Issuer",
                                                     "pretty"));

        // stop adding crl extensions

        // start adding crl entry extensions

        revokedCertificate.getExtensions().add(new Extension(
                                                             "digitalSignature, keyEncipherment",
                                                                 "2.5.29.15",
                                                                 "true",
                                                                 "Key Usage",
                                                                 "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "1.2.3.4.5",
                                                                 "2.5.29.32",
                                                                 "false",
                                                                 "Certificate Polices",
                                                                 "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "true",
                                                                 "2.5.29.19",
                                                                 "true",
                                                                 "Basic Constraints",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             sanValue,
                                                                 "2.5.29.17",
                                                                 "false",
                                                                 "Subject Alternative Name",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             sanValue,
                                                                 "2.5.29.18",
                                                                 "false",
                                                                 "Issuer Alternative Name",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "BBwwGjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB",
                                                                 "2.5.29.9",
                                                                 "false",
                                                                 "Subject Directory Attibutes",
                                                                 "raw"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "1.2,1.3.3.4|2.5.6.5.6,1.0.7.8",
                                                                 "2.5.29.33",
                                                                 "true",
                                                                 "Policy Mappings",
                                                                 "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "permitted:dNSName=owneddn.de,excluded:rfc822Name=a@a.de",
                                                                 "2.5.29.30",
                                                                 "true",
                                                                 "Name Constraints",
                                                                 "pretty"));

        // revokedCertificate.getExtensions().add(new Extension(
        // "requireExplicitPolicy=-2,inhibitPolicyMapping=200",
        // "2.5.29.36",
        // "false", // SUN requires false although this extension
        // // should be critical
        // "Policy Constraints",
        // "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
                                                                 "2.5.29.37",
                                                                 "false",
                                                                 "Extended Key Usage",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             crlDistributionPointValue,
                                                                 "2.5.29.31",
                                                                 "false",
                                                                 "CRL Distribution Points",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension("48", "2.5.29.54", "true", "Inhibit anyPolicy", "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             crlDistributionPointValue,
                                                                 "2.5.29.46",
                                                                 "false",
                                                                 "Freshest CRL",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "https://ocsp.url.de/ocsp",
                                                                 "1.3.6.1.5.5.7.1.1",
                                                                 "false",
                                                                 "Authority Information Access",
                                                                 "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "https://ca.url.de/repository",
                                                                 "1.3.6.1.5.5.7.1.11",
                                                                 "false",
                                                                 "Subject Information Access",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "http://crl.url.de/crl.crl",
                                                                 "2.5.29.28",
                                                                 "true",
                                                                 "Issuing Distribution Point",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));

        revokedCertificate.getExtensions().add(new Extension(
                                                             "28",
                                                                 "2.5.29.27",
                                                                 "true",
                                                                 "Delta CRL Indicator",
                                                                 "pretty"));

        revokedCertificate.getExtensions().add(new Extension("3", "2.5.29.21", "true", "Reason Code", "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "-2D,GEN",
                                                                 "2.5.29.24",
                                                                 "false",
                                                                 "Invalidity Date",
                                                                 "pretty"));
        revokedCertificate.getExtensions().add(new Extension(
                                                             "CN=Test Issuer, C=DE|UTF8",
                                                                 "2.5.29.29",
                                                                 "false",
                                                                 "Certificate Issuer",
                                                                 "pretty"));

        revokedCertificate.setRefid(id);
        revokedCertificate.setRevocationDate(new RevocationDate("-3D", "UTC"));
        revokedCertificates.add(revokedCertificate);

        // stop adding crl entry extensions

        xmlCRL.setRevokedCertificates(revokedCertificates);

        TestToolCRL technicalCRL = new TestToolCRL(xmlCRL);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCRL.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL asn1CRL = (X509CRL) cf.generateCRL(bais);
        bais.close();

        X509CRLEntry revokedCertificateFromCRL =
            asn1CRL.getRevokedCertificate(certificateCreator.getRootCACertificate().getSerialNumber());

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, asn1CRL.getThisUpdate());
        crlBuilder.setNextUpdate(asn1CRL.getNextUpdate());

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();
        // Authority Key Identifier
        org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki =
            util.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(certificateCreator.getRootCACertificate()
                                                                                                 .getPublicKey().getEncoded()));
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, aki);

        // Subject Key Identifier
        // not used here

        // Key Usage
        org.bouncycastle.asn1.x509.KeyUsage keyUsage =
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, keyUsage);

        // Certificate Policies
        org.bouncycastle.asn1.x509.CertificatePolicies certificatePolicies =
            new CertificatePolicies(new PolicyInformation(
                                                          new ASN1ObjectIdentifier("1.2.3.4.5")));
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, false,
                                         certificatePolicies);
        // Basic Constraints
        org.bouncycastle.asn1.x509.BasicConstraints basicConstraints = new BasicConstraints(true);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, basicConstraints);

        // Subject Alternative Name

        GeneralName[] generalNameArray = new GeneralName[3];
        generalNameArray[0] = new GeneralName(GeneralName.rfc822Name, "a@a.de");
        generalNameArray[1] = new GeneralName(GeneralName.dNSName, "owneddn.de");
        generalNameArray[2] = new GeneralName(GeneralName.iPAddress, "127.0.0.1");
        GeneralNames generalNames = new GeneralNames(generalNameArray);

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                                         generalNames);

        // Issuer Alternative Name
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName, false,
                                         generalNames);

        // Subject Directory Attributes
        Vector<Attribute> values = new Vector<Attribute>();
        values.add(new Attribute(
                                 CMSAttributes.contentType,
                                     new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));

        org.bouncycastle.asn1.x509.SubjectDirectoryAttributes subjectDirectoryAttributes =
            new SubjectDirectoryAttributes(values);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes, false,
                                         subjectDirectoryAttributes);

        // Policy Mappings

        CertPolicyId[] issuerPolicies = new CertPolicyId[2];
        CertPolicyId[] subjectPolicies = new CertPolicyId[2];
        issuerPolicies[0] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.2"));
        issuerPolicies[1] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("2.5.6.5.6"));
        subjectPolicies[0] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.3.3.4"));
        subjectPolicies[1] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.0.7.8"));
        PolicyMappings policyMappings = new PolicyMappings(issuerPolicies, subjectPolicies);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.policyMappings, true, policyMappings);

        // Name Constraints

        GeneralSubtree[] permittedSubtrees = new GeneralSubtree[1];
        permittedSubtrees[0] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "owneddn.de"));

        GeneralSubtree[] excludedSubtrees = new GeneralSubtree[1];
        excludedSubtrees[0] = new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "a@a.de"));

        NameConstraints nameConstraints = new NameConstraints(permittedSubtrees, excludedSubtrees);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.nameConstraints, true, nameConstraints);

        // Policy Constraints
        //
        PolicyConstraints policyConstraints = new PolicyConstraints(new BigInteger("1"), new BigInteger("1"));

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.policyConstraints, false,
                                         policyConstraints);

        // Extended Key Usage
        KeyPurposeId[] ekuIds = new KeyPurposeId[2];
        ekuIds[0] = KeyPurposeId.id_kp_serverAuth;
        ekuIds[1] = KeyPurposeId.id_kp_clientAuth;
        ExtendedKeyUsage eku = new ExtendedKeyUsage(ekuIds);
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, eku);

        // CRL Distribution Points

        generalNameArray = new GeneralName[2];
        generalNameArray[0] = new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.url.de/crl.crl");
        generalNameArray[1] = new GeneralName(
                                              GeneralName.uniformResourceIdentifier,
                                                  "ldap://ldap.url.de/cn=crl,dc=de?certificateRevocationList");

        generalNames = new GeneralNames(generalNameArray);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint[] distributionPoints = new DistributionPoint[1];
        distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
        CRLDistPoint crlDistributionPoint = new CRLDistPoint(distributionPoints);

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints, false,
                                         crlDistributionPoint);

        // Inhibit anyPolicy
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy, true,
                                         new ASN1Integer(new BigInteger(
                                                                        "48")));

        // Freshest CRL

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.freshestCRL, false, crlDistributionPoint);

        // Authority Information Access

        org.bouncycastle.asn1.x509.AuthorityInformationAccess aia =
            new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                                                                      new AccessDescription(
                                                                                            AccessDescription.id_ad_ocsp,
                                                                                                new GeneralName(
                                                                                                                GeneralName.uniformResourceIdentifier,
                                                                                                                    "https://ocsp.url.de/ocsp")));

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess, false, aia);

        // Subject Information Access

        org.bouncycastle.asn1.x509.AuthorityInformationAccess sia =
            new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                                                                      new AccessDescription(
                                                                                            AccessDescription.id_ad_caIssuers,
                                                                                                new GeneralName(
                                                                                                                GeneralName.uniformResourceIdentifier,
                                                                                                                    "https://ca.url.de/repository")));

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess, false, sia);

        // Issuing Distribution Point

        // generalNameArray = new GeneralName[1];
        // generalNameArray[0] = new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.url.de/crl.crl");
        //
        // generalNames = new GeneralNames(generalNameArray);
        // distributionPointName = new DistributionPointName(generalNames);
        // distributionPoints = new DistributionPoint[1];
        // distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
        // CRLDistPoint issuingDistributionPoint = new CRLDistPoint(distributionPoints);
        //
        // extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint, false,
        // issuingDistributionPoint);

        generalNameArray = new GeneralName[1];
        generalNameArray[0] = new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.url.de/crl.crl");
        generalNames = new GeneralNames(generalNameArray);
        distributionPointName = new DistributionPointName(generalNames);

        IssuingDistributionPoint issuingDistributionPointNew =
            new IssuingDistributionPoint(distributionPointName, false, false, null, false, false);

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint, true,
                                         issuingDistributionPointNew.getEncoded());

        // CRL Number

        org.bouncycastle.asn1.x509.CRLNumber crlNumber = new CRLNumber(new BigInteger("1234"));
        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, true, crlNumber);

        // Delta CRL Indicator

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator, true,
                                         new ASN1Integer(new BigInteger(
                                                                        "28")));

        // CRL Reason

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.reasonCode, true,
                                         new ASN1Enumerated(org.bouncycastle.asn1.x509.CRLReason.affiliationChanged));

        // Invalidity Date

        byte[] rawInvalidityDate =
            asn1CRL.getExtensionValue(org.bouncycastle.asn1.x509.Extension.invalidityDate.getId());

        bais = new ByteArrayInputStream(rawInvalidityDate);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DEROctetString rawExtensionValue = (DEROctetString) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        bais = new ByteArrayInputStream(rawExtensionValue.getOctets());
        asn1InputStream = new ASN1InputStream(bais);
        ASN1GeneralizedTime readGeneralizedTime = (ASN1GeneralizedTime) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        ASN1GeneralizedTime generalizedTime = new ASN1GeneralizedTime(readGeneralizedTime.getDate());

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.invalidityDate, false, generalizedTime);

        // Certificate Issuer

        X500Name name = new X500Name("CN=Test Issuer, C=DE");
        generalNames = new GeneralNames(new GeneralName(name));

        extensionsGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.certificateIssuer, false, generalNames);

        // ----

        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.keyUsage));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.policyMappings));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.nameConstraints));
        // crlBuilder.addExtension(extensionsGenerator.generate()
        // .getExtension(org.bouncycastle.asn1.x509.Extension.policyConstraints));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.freshestCRL));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.reasonCode));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.invalidityDate));
        crlBuilder.addExtension(extensionsGenerator.generate()
                                                   .getExtension(org.bouncycastle.asn1.x509.Extension.certificateIssuer));

        ExtensionsGenerator crlEntryExtensionsGenerator = new ExtensionsGenerator();

        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.keyUsage));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.policyMappings));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.nameConstraints));
        // crlEntryextensionsGenerator.addExtension(extensionsGenerator.generate()
        // .getExtension(org.bouncycastle.asn1.x509.Extension.policyConstraints));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.freshestCRL));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.reasonCode));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.invalidityDate));
        crlEntryExtensionsGenerator.addExtension(extensionsGenerator.generate()
                                                                    .getExtension(org.bouncycastle.asn1.x509.Extension.certificateIssuer));

        crlBuilder.addCRLEntry(certificateCreator.getRootCACertificate().getSerialNumber(),
                               revokedCertificateFromCRL.getRevocationDate(), crlEntryExtensionsGenerator.generate());

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL highLevelCRL = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        Assertions.assertTrue(Arrays.equals(asn1CRL.getTBSCertList(), highLevelCRL.getTBSCertList()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getSignature(), highLevelCRL.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1CRL.getEncoded(), highLevelCRL.getEncoded()));

        highLevelCRL.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1CRL.verify(certificateCreator.getRootCACertificate().getPublicKey());

        objectCache.clear();

    }

}
