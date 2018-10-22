
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
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
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import de.mtg.certpathtest.pkiobjects.SubjectDN;

/**
 *
 * Units tests for the main functionality of {@Link TestToolCertificate}.
 *
 */
public class TestToolCertificateTest
{

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     * Tests the creation of a simple RSA certificate with an encoded key.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testRSA() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        BigInteger randomSN = new BigInteger(32, random);

        String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
            new String(Base64.encode(certificateCreator.getRootCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getRootCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(randomSN.toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     issuer, randomSN,
                                                                                         asn1Certificate.getNotBefore(),
                                                                                         asn1Certificate.getNotAfter(),
                                                                                         subject,
                                                                                         SubjectPublicKeyInfo.getInstance(certificateCreator.getRootCACertificate()
                                                                                                                                            .getPublicKey()
                                                                                                                                            .getEncoded()));

        PrivateKey privateKey = certificateCreator.getRootCAPrivateKey();

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        Assert.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getSignature(), highLevelCertificate.getSignature()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getEncoded(), highLevelCertificate.getEncoded()));

        highLevelCertificate.verify(certificateCreator.getRootCACertificate().getPublicKey());
        asn1Certificate.verify(certificateCreator.getRootCACertificate().getPublicKey());

        // check for encoding of DNs

        X500Name name = new X500Name(highLevelCertificate.getSubjectDN().getName());
        ASN1Sequence seq;
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(asn1Certificate.getSubjectX500Principal().getEncoded()))
            {
                 seq = (ASN1Sequence) asn1InputStream.readObject();
            }

        Assert.assertTrue(Arrays.equals(name.getEncoded(), seq.getEncoded()));

    }

    /**
     *
     * Tests the creation of a simple RSA certificate with a generated key.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testRSAKeyGen() throws Exception
    {
        Random random = new Random();

        BigInteger randomSN = new BigInteger(32, random);

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(randomSN.toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     issuer, randomSN,
                                                                                         asn1Certificate.getNotBefore(),
                                                                                         asn1Certificate.getNotAfter(),
                                                                                         subject,
                                                                                         SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                                                                                         .getEncoded()));

        PrivateKey privateKey = ObjectCache.getInstance().getPrivateKey(id);

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        Assert.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getSignature(), highLevelCertificate.getSignature()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getEncoded(), highLevelCertificate.getEncoded()));

        highLevelCertificate.verify(asn1Certificate.getPublicKey());
        asn1Certificate.verify(asn1Certificate.getPublicKey());
    }

    /**
     *
     * Tests the creation of a simple EC certificate with an encoded key.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testEC() throws Exception
    {

        CertificateCreator certificateCreator = CertificateCreator.getInstance();

        Random random = new Random();

        BigInteger randomSN = new BigInteger(32, random);

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        String encodedPublicKey =
            new String(Base64.encode(certificateCreator.getSubCACertificate().getPublicKey().getEncoded()));

        String encodedPrivateKey = new String(Base64.encode(certificateCreator.getSubCAPrivateKey().getEncoded()));

        String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(randomSN.toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
        xmlCertificate.setSignature("1.2.840.10045.4.3.2");
        xmlCertificate.setVerifiedBy(id);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     issuer, randomSN,
                                                                                         asn1Certificate.getNotBefore(),
                                                                                         asn1Certificate.getNotAfter(),
                                                                                         subject,
                                                                                         SubjectPublicKeyInfo.getInstance(certificateCreator.getSubCACertificate()
                                                                                                                                            .getPublicKey()
                                                                                                                                            .getEncoded()));

        PrivateKey privateKey = certificateCreator.getSubCAPrivateKey();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        highLevelCertificate.verify(certificateCreator.getSubCACertificate().getPublicKey());
        asn1Certificate.verify(certificateCreator.getSubCACertificate().getPublicKey());

        Assert.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));

    }

    /**
     *
     * Tests the creation of a simple EC certificate with a generated key.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testECKeyGen() throws Exception
    {

        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);
        BigInteger randomSN = new BigInteger(32, random);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(randomSN.toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("ECDSA,prime256v1", "pretty"));
        xmlCertificate.setSignature("1.2.840.10045.4.3.2");
        xmlCertificate.setVerifiedBy(id);

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     issuer, randomSN,
                                                                                         asn1Certificate.getNotBefore(),
                                                                                         asn1Certificate.getNotAfter(),
                                                                                         subject,
                                                                                         SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                                                                                         .getEncoded()));

        PrivateKey privateKey = ObjectCache.getInstance().getPrivateKey(id);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        highLevelCertificate.verify(asn1Certificate.getPublicKey());
        asn1Certificate.verify(asn1Certificate.getPublicKey());

        Assert.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));

    }

    /**
     *
     * Tests the creation of an RSA certificate with a generated key and some extensions.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testRSAWithExtensions() throws Exception
    {
        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        BigInteger randomSN = new BigInteger(32, random);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber(randomSN.toString());
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        String sanValue = "rfc822Name=a@a.de,dNSName=owneddn.de,iPAddress=127.0.0.1";
        String crlDistributionPointValue =
            "http://crl.url.de/crl.crl|ldap://ldap.url.de/cn=crl,dc=de?certificateRevocationList";

        xmlCertificate.getExtensions().add(new Extension("", "2.5.29.35", "false", "AKI", "pretty"));
        xmlCertificate.getExtensions().add(new Extension("", "2.5.29.14", "false", "SKI", "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                                                         "digitalSignature, keyEncipherment",
                                                             "2.5.29.15",
                                                             "true",
                                                             "Key Usage",
                                                             "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                                                         "1.2.3.4.5",
                                                             "2.5.29.32",
                                                             "false",
                                                             "Certificate Polices",
                                                             "pretty"));
        xmlCertificate.getExtensions().add(new Extension("true", "2.5.29.19", "true", "Basic Constraints", "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         sanValue,
                                                             "2.5.29.17",
                                                             "false",
                                                             "Subject Alternative Name",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         sanValue,
                                                             "2.5.29.18",
                                                             "false",
                                                             "Issuer Alternative Name",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "BBwwGjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB",
                                                             "2.5.29.9",
                                                             "false",
                                                             "Subject Directory Attibutes",
                                                             "raw"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "1.2,1.3.3.4|2.5.6.5.6,1.0.7.8",
                                                             "2.5.29.33",
                                                             "true",
                                                             "Policy Mappings",
                                                             "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                                                         "permitted:dNSName=owneddn.de,excluded:rfc822Name=a@a.de",
                                                             "2.5.29.30",
                                                             "true",
                                                             "Name Constraints",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "requireExplicitPolicy=1,inhibitPolicyMapping=1",
                                                             "2.5.29.36",
                                                             "true",
                                                             "Policy Constraints",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
                                                             "2.5.29.37",
                                                             "false",
                                                             "Extended Key Usage",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         crlDistributionPointValue,
                                                             "2.5.29.31",
                                                             "false",
                                                             "CRL Distribution Points",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension("48", "2.5.29.54", "true", "Inhibit anyPolicy", "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         crlDistributionPointValue,
                                                             "2.5.29.46",
                                                             "false",
                                                             "Freshest CRL",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "https://ocsp.url.de/ocsp",
                                                             "1.3.6.1.5.5.7.1.1",
                                                             "false",
                                                             "Authority Information Access",
                                                             "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                                                         "https://ca.url.de/repository",
                                                             "1.3.6.1.5.5.7.1.11",
                                                             "false",
                                                             "Subject Information Access",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension(
                                                         "http://crl.url.de/crl.crl",
                                                             "2.5.29.28",
                                                             "true",
                                                             "Issuing Distribution Point",
                                                             "pretty"));

        xmlCertificate.getExtensions().add(new Extension("1234", "2.5.29.20", "true", "CRL Number", "pretty"));

        xmlCertificate.getExtensions().add(new Extension("28", "2.5.29.27", "true", "Delta CRL Indicator", "pretty"));

        xmlCertificate.getExtensions().add(new Extension("3", "2.5.29.21", "true", "Reason Code", "pretty"));
        xmlCertificate.getExtensions().add(new Extension("-2D,GEN", "2.5.29.24", "false", "Invalidity Date", "pretty"));
        xmlCertificate.getExtensions().add(new Extension(
                                                         "CN=Test, C=DE|UTF8",
                                                             "2.5.29.29",
                                                             "false",
                                                             "Certificate Issuer",
                                                             "pretty"));

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     issuer, randomSN,
                                                                                         asn1Certificate.getNotBefore(),
                                                                                         asn1Certificate.getNotAfter(),
                                                                                         subject,
                                                                                         SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                                                                                         .getEncoded()));

        JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();

        // Authority Key Identifier
        org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki =
            util.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                                              .getEncoded()));
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, aki);

        // Subject Key Identifier
        org.bouncycastle.asn1.x509.SubjectKeyIdentifier ski =
            util.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                                            .getEncoded()));
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, ski);

        // Key Usage
        org.bouncycastle.asn1.x509.KeyUsage keyUsage =
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, keyUsage);

        // Certificate Policies
        org.bouncycastle.asn1.x509.CertificatePolicies certificatePolicies =
            new CertificatePolicies(new PolicyInformation(
                                                          new ASN1ObjectIdentifier("1.2.3.4.5")));
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, false,
                                          certificatePolicies);
        // Basic Constraints
        org.bouncycastle.asn1.x509.BasicConstraints basicConstraints = new BasicConstraints(true);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                                          basicConstraints);

        // Subject Alternative Name

        GeneralName[] generalNameArray = new GeneralName[3];
        generalNameArray[0] = new GeneralName(GeneralName.rfc822Name, "a@a.de");
        generalNameArray[1] = new GeneralName(GeneralName.dNSName, "owneddn.de");
        generalNameArray[2] = new GeneralName(GeneralName.iPAddress, "127.0.0.1");
        GeneralNames generalNames = new GeneralNames(generalNameArray);

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                                          generalNames);

        // Issuer Alternative Name
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName, false,
                                          generalNames);

        // Subject Directory Attributes
        Vector<Attribute> values = new Vector<Attribute>();
        values.add(new Attribute(
                                 CMSAttributes.contentType,
                                     new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));

        org.bouncycastle.asn1.x509.SubjectDirectoryAttributes subjectDirectoryAttributes =
            new SubjectDirectoryAttributes(values);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes, false,
                                          subjectDirectoryAttributes);

        // Policy Mappings

        CertPolicyId[] issuerPolicies = new CertPolicyId[2];
        CertPolicyId[] subjectPolicies = new CertPolicyId[2];
        issuerPolicies[0] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.2"));
        issuerPolicies[1] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("2.5.6.5.6"));
        subjectPolicies[0] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.3.3.4"));
        subjectPolicies[1] = CertPolicyId.getInstance(new ASN1ObjectIdentifier("1.0.7.8"));
        PolicyMappings policyMappings = new PolicyMappings(issuerPolicies, subjectPolicies);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.policyMappings, true, policyMappings);

        // Name Constraints

        GeneralSubtree[] permittedSubtrees = new GeneralSubtree[1];
        permittedSubtrees[0] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "owneddn.de"));

        GeneralSubtree[] excludedSubtrees = new GeneralSubtree[1];
        excludedSubtrees[0] = new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "a@a.de"));

        NameConstraints nameConstraints = new NameConstraints(permittedSubtrees, excludedSubtrees);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.nameConstraints, true, nameConstraints);

        // Policy Constraints

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, new ASN1Integer(1)));
        v.add(new DERTaggedObject(false, 1, new ASN1Integer(1)));

        byte[] encoded = new DERSequence(v).getEncoded();
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.policyConstraints, true, encoded);

        // Extended Key Usage
        KeyPurposeId[] ekuIds = new KeyPurposeId[2];
        ekuIds[0] = KeyPurposeId.id_kp_serverAuth;
        ekuIds[1] = KeyPurposeId.id_kp_clientAuth;
        ExtendedKeyUsage eku = new ExtendedKeyUsage(ekuIds);
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, eku);

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

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints, false,
                                          crlDistributionPoint);

        // Inhibit anyPolicy
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy, true,
                                          new ASN1Integer(new BigInteger(
                                                                         "48")));

        // Freshest CRL

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.freshestCRL, false,
                                          crlDistributionPoint);

        // Authority Information Access

        org.bouncycastle.asn1.x509.AuthorityInformationAccess aia =
            new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                                                                      new AccessDescription(
                                                                                            AccessDescription.id_ad_ocsp,
                                                                                                new GeneralName(
                                                                                                                GeneralName.uniformResourceIdentifier,
                                                                                                                    "https://ocsp.url.de/ocsp")));

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess, false, aia);

        // Subject Information Access

        org.bouncycastle.asn1.x509.AuthorityInformationAccess sia =
            new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                                                                      new AccessDescription(
                                                                                            AccessDescription.id_ad_caIssuers,
                                                                                                new GeneralName(
                                                                                                                GeneralName.uniformResourceIdentifier,
                                                                                                                    "https://ca.url.de/repository")));

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess, false, sia);

        // Issuing Distribution Point

        generalNameArray = new GeneralName[1];
        generalNameArray[0] = new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.url.de/crl.crl");
        generalNames = new GeneralNames(generalNameArray);
        distributionPointName = new DistributionPointName(generalNames);

        IssuingDistributionPoint issuingDistributionPointNew =
            new IssuingDistributionPoint(distributionPointName, false, false, null, false, false);

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint, true,
                                          issuingDistributionPointNew.getEncoded());

        // CRL Number

        org.bouncycastle.asn1.x509.CRLNumber crlNumber = new CRLNumber(new BigInteger("1234"));
        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, true, crlNumber);

        // Delta CRL Indicator

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator, true,
                                          new ASN1Integer(new BigInteger(
                                                                         "28")));

        // CRL Reason

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.reasonCode, true,
                                          new ASN1Enumerated(org.bouncycastle.asn1.x509.CRLReason.affiliationChanged));
        // Invalidity Date

        byte[] rawInvalidityDate =
            asn1Certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.invalidityDate.getId());

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

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.invalidityDate, false, generalizedTime);

        // Certificate Issuer

        X500Name name = new X500Name("CN=Test, C=DE");
        generalNames = new GeneralNames(new GeneralName(name));

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.certificateIssuer, false, generalNames);

        // Starting signing

        PrivateKey privateKey = ObjectCache.getInstance().getPrivateKey(id);

        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        Assert.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getSignature(), highLevelCertificate.getSignature()));
        Assert.assertTrue(Arrays.equals(asn1Certificate.getEncoded(), highLevelCertificate.getEncoded()));

        highLevelCertificate.verify(asn1Certificate.getPublicKey());
        asn1Certificate.verify(asn1Certificate.getPublicKey());
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
