/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.CertificateCreator;
import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.security.asn1.x509.util.Util;

/**
 * Test of {@link SimpleTBSCertificate}.
 */
public class SimpleTBSCertificateTest
{
    private static Logger logger = LoggerFactory.getLogger(SimpleTBSCertificateTest.class);

    private static final Provider BC = new BouncyCastleProvider();

    private CertificateCreator certificateCreator;

    static
    {
        Security.addProvider(BC);
    }

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {

        certificateCreator = CertificateCreator.getInstance();
    }

    /**
     * Tests building a TBS certificate from bytes.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void buildRsaFromBytes() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);
        logger.debug("inCert: {}", ASN1Dump.dumpAsString(inCert, true));

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);

        SimpleTBSCertificate outTbsCert = SimpleTBSCertificate.getInstance(inTbsCertBytes);
        byte[] outTbsCertBytes = outTbsCert.getEncoded(ASN1Encoding.DER);

        Assert.assertArrayEquals(inTbsCertBytes, outTbsCertBytes);
    }

    /**
     * Tests building a TBS certificate from bytes.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void buildEcKeyRSASignatureFromBytes() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getSubCACertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);
        logger.debug("inCert: {}", ASN1Dump.dumpAsString(inCert, true));

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);

        SimpleTBSCertificate outTbsCert = SimpleTBSCertificate.getInstance(inTbsCertBytes);
        byte[] outTbsCertBytes = outTbsCert.getEncoded(ASN1Encoding.DER);

        Assert.assertArrayEquals(inTbsCertBytes, outTbsCertBytes);
    }

    /**
     * Tests building a TBS certificate from bytes.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void buildEcKeyECSignatureFromBytes() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getEeCertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);
        logger.debug("inCert: {}", ASN1Dump.dumpAsString(inCert, true));

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);

        SimpleTBSCertificate outTbsCert = SimpleTBSCertificate.getInstance(inTbsCertBytes);
        byte[] outTbsCertBytes = outTbsCert.getEncoded(ASN1Encoding.DER);

        Assert.assertArrayEquals(inTbsCertBytes, outTbsCertBytes);
    }

    /**
     * Tests building a TBS certificate from components.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void buildFromComponents() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);

        SimpleTBSCertificate outTbsCert = new SimpleTBSCertificate();

        outTbsCert.setVersion(inTbsCert.getVersion());
        outTbsCert.setSerialNumber(inTbsCert.getSerialNumber());
        outTbsCert.setSignature(inTbsCert.getSignature());
        outTbsCert.setIssuer(inTbsCert.getIssuer());
        outTbsCert.setStartDate(inTbsCert.getStartDate());
        outTbsCert.setEndDate(inTbsCert.getEndDate());
        outTbsCert.setSubject(inTbsCert.getSubject());
        outTbsCert.setSubjectPublicKeyInfo(inTbsCert.getSubjectPublicKeyInfo());
        outTbsCert.setIssuerUniqueID(inTbsCert.getIssuerUniqueID());
        outTbsCert.setSubjectUniqueID(inTbsCert.getSubjectUniqueID());
        outTbsCert.setExtensions(inTbsCert.getExtensions());

        byte[] outTbsCertBytes = outTbsCert.getEncoded(ASN1Encoding.DER);
        Assert.assertArrayEquals(inTbsCertBytes, outTbsCertBytes);
    }

    /**
     * Tests adding extensions to TBS certificate.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void addExtensions() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();

        // clone
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);
        SimpleTBSCertificate tbsCert = SimpleTBSCertificate.getInstance(inTbsCertBytes);

        List<SimpleExtension> extensions = tbsCert.getExtensions();
        Assert.assertNotNull(extensions);
        Assert.assertFalse(extensions.isEmpty());

        List<SimpleExtension> newExtensions = new ArrayList<SimpleExtension>();
        newExtensions.addAll(extensions);
        newExtensions.addAll(extensions);
        tbsCert.setExtensions(newExtensions);

        Assert.assertEquals(2 * extensions.size(), newExtensions.size());

        byte[] tbsCertBytes = tbsCert.getEncoded(ASN1Encoding.DER);
        SimpleTBSCertificate outTbsCert = SimpleTBSCertificate.getInstance(tbsCertBytes);
        Assert.assertEquals(newExtensions.size(), outTbsCert.getExtensions().size());

        logger.debug("outTbsCert: {}", ASN1Dump.dumpAsString(outTbsCert, true));
    }

    /**
     * Tests encoding default incorrectly in extensions of TBS certificate.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void encodeDefaultFalse() throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);

        SimpleTBSCertificate inTbsCert = inCert.getTbsCertificate();

        // clone
        byte[] inTbsCertBytes = inTbsCert.getEncoded(ASN1Encoding.DER);
        SimpleTBSCertificate tbsCert = SimpleTBSCertificate.getInstance(inTbsCertBytes);

        List<SimpleExtension> extensions = tbsCert.getExtensions();
        Assert.assertNotNull(extensions);
        Assert.assertFalse(extensions.isEmpty());

        for (SimpleExtension ext : extensions)
        {
            ext.setCritical(ASN1Boolean.FALSE);
        }

        // clone
        byte[] tbsCertBytes = tbsCert.getEncoded(ASN1Encoding.DER);
        SimpleTBSCertificate outTbsCert = SimpleTBSCertificate.getInstance(tbsCertBytes);

        logger.debug("outTbsCert: {}", ASN1Dump.dumpAsString(outTbsCert, true));

        List<SimpleExtension> outExtensions = outTbsCert.getExtensions();
        Assert.assertNotNull(outExtensions);
        Assert.assertFalse(outExtensions.isEmpty());

        for (SimpleExtension ext : outExtensions)
        {
            Assert.assertEquals(ASN1Boolean.FALSE, ext.getCritical());
        }
    }

    /**
     * Checks version.
     *
     * @throws IOException if encoding errors occur.
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     */
    @Test
    public void checkVersion() throws IOException, GeneralSecurityException
    {
        byte[] certBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(certBytes);
        SimpleTBSCertificate tbsCert = cert.getTbsCertificate();

        ASN1Integer version = tbsCert.getVersion();
        int versionNumber = tbsCert.getVersionNumber();
        logger.debug("version: {}", version);
        logger.debug("versionNumber: " + versionNumber);
        Assert.assertEquals(BigInteger.valueOf(2), version.getValue());
        Assert.assertEquals(3, versionNumber);
    }

    /**
     *
     * Checks whether the public key of a decoded certificate can be parsed.
     *
     * @throws IOException if encoding errors occur.
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     */
    @Test
    public void checkRSAPublicKey() throws IOException, GeneralSecurityException
    {
        byte[] certBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(certBytes);
        SimpleTBSCertificate tbsCert = cert.getTbsCertificate();
        SubjectPublicKeyInfo spki = tbsCert.getSubjectPublicKeyInfo();
        DERBitString pkData = spki.getPublicKeyData();
        byte[] keyData = pkData.getBytes();
        // ASN1Primitive asn1KeyData = ASN1Primitive.fromByteArray(keyData);
        // logger.debug("asn1KeyData: {}", ASN1Dump.dumpAsString(asn1KeyData, true));
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPubK = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(keyData);
        BigInteger modulus = rsaPubK.getModulus();
        Assert.assertNotNull(modulus);
        Assert.assertNotNull(rsaPubK.getPublicExponent());
        logger.debug("modulus hex: {}", modulus.toString(16));
    }

    /**
     *
     * Checks whether a v1 certificate can be built by the implementation on the DER Basis.
     *
     * @throws CertificateException if encoding errors regarding certificates occur.
     * @throws IOException if encoding errors occur.
     */
    @Test
    public void buildMinV1RsaCert() throws CertificateException, IOException
    {
        ASN1Integer serialNumber = new ASN1Integer(0);

        // ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.5");
        ASN1ObjectIdentifier sigAlgOID = PKCSObjectIdentifiers.sha1WithRSAEncryption;
        AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(sigAlgOID);

        X500Name issuer = new X500Name("CN=issuer");
        X500Name subject = new X500Name("CN=subject");

        Date now = new Date();
        Date later = new Date(now.getTime() + 1000L * 60 * 60 * 24 * 365);
        Time startDate = new Time(now);
        Time endDate = new Time(later);

        // ASN1ObjectIdentifier keyAlgOID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
        ASN1ObjectIdentifier keyAlgOID = PKCSObjectIdentifiers.rsaEncryption;
        AlgorithmIdentifier keyAlgorithm = new AlgorithmIdentifier(keyAlgOID);
        BigInteger modulus = new BigInteger(
                                            "b62586596b0634775c1dba354599b2d7467a3f820bd1be32a9532428dc5731a378884baa26fc0186c4c6e196ae5a2089fdd5f6e1a78293bdbdfca511d228c9aba48bcdff13d0b2e9d149386abfd9b65ea982351c112ce98f609f85fc33a3bc421c59d98968cf9937ae071aaa8afc6889362c154e01e2da0cff5e64775ef9c5bdd12ac144fe2983bda2b8b3f86343c35c01528a8173799c40a13de68512596831792aeda4ebe5f5c59204790ea040e5e146b21c4d9b825e3d6f1db38ad9d80501937274157d8b26b263070f4fc8272ab77f72ab414dbd4549eb61396e04f3c8f49410cf7bcf224c053c08ba1850d74a0264cf9c594ccc9701b9afe98de194722d",
                                                16);
        BigInteger exponent = BigInteger.valueOf(0x10001);
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPubK =
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(modulus, exponent);
        byte[] keyData = rsaPubK.getEncoded(ASN1Encoding.DER);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(keyAlgorithm, keyData);

        SimpleTBSCertificate tbsCert = new SimpleTBSCertificate();

        tbsCert.setSerialNumber(serialNumber);
        tbsCert.setSignature(signatureAlgorithm);
        tbsCert.setIssuer(issuer);
        tbsCert.setStartDate(startDate);
        tbsCert.setEndDate(endDate);
        tbsCert.setSubject(subject);
        tbsCert.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        SimpleCertificate cert = new SimpleCertificate();

        cert.setTbsCertificate(tbsCert);
        cert.setSignatureAlgorithm(signatureAlgorithm);
        cert.setSignature(new byte[0]);

        logger.debug("cert: {}", ASN1Dump.dumpAsString(cert, true));

        byte[] certEncoded = cert.getEncoded(ASN1Encoding.DER);
        ByteArrayInputStream inStream = new ByteArrayInputStream(certEncoded);

        CertificateFactory certFac = CertificateFactory.getInstance("X.509");
        Certificate xCert = certFac.generateCertificate(inStream);
        logger.debug("xCert: {}", xCert);
    }

    /**
     *
     * Checks whether a v1 certificate can be built by the implementation on the DER Basis.
     *
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     * @throws IOException if encoding errors occur.
     */
    @Test
    public void buildSelfSignedV1RsaCert() throws GeneralSecurityException, IOException
    {
        ASN1Integer serialNumber = new ASN1Integer(0);

        // String sigOID = "1.2.840.113549.1.1.5";
        String sigOID = PKCSObjectIdentifiers.sha1WithRSAEncryption.getId();
        ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(sigOID);
        AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(sigAlgOID);

        X500Name subject = new X500Name("CN=subject");
        X500Name issuer = subject;

        Date now = new Date();
        Date later = new Date(now.getTime() + 1000L * 60 * 60 * 24 * 365);
        Time startDate = new Time(now);
        Time endDate = new Time(later);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
        SubjectPublicKeyInfo subjectPublicKeyInfo = Util.buildSubjectPublicKeyInfo(keyPair.getPublic());

        SimpleTBSCertificate tbsCert = new SimpleTBSCertificate();

        tbsCert.setSerialNumber(serialNumber);
        tbsCert.setSignature(signatureAlgorithm);
        tbsCert.setIssuer(issuer);
        tbsCert.setStartDate(startDate);
        tbsCert.setEndDate(endDate);
        tbsCert.setSubject(subject);
        tbsCert.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        SimpleCertificate cert = new SimpleCertificate();

        cert.setTbsCertificate(tbsCert);
        cert.setSignatureAlgorithm(signatureAlgorithm);

        Signature signer = Signature.getInstance(sigOID);
        signer.initSign(keyPair.getPrivate());
        signer.update(tbsCert.getEncoded(ASN1Encoding.DER));
        byte[] signature = signer.sign();
        cert.setSignature(signature);

        logger.debug("cert: {}", ASN1Dump.dumpAsString(cert, true));

        byte[] certEncoded = cert.getEncoded(ASN1Encoding.DER);
        ByteArrayInputStream inStream = new ByteArrayInputStream(certEncoded);

        CertificateFactory certFac = CertificateFactory.getInstance("X.509");
        Certificate xCert = certFac.generateCertificate(inStream);
        logger.debug("xCert: {}", xCert);
        X509Certificate x509Cert = (X509Certificate) xCert;

        x509Cert.verify(keyPair.getPublic());
    }

    /**
     *
     * Checks whether a TBS certificate with extensions can be built by the implementation on the DER Basis.
     *
     * @throws CertificateException if encoding errors regarding certificates occur.
     * @throws IOException if encoding errors occur.
     */
    @Test
    public void buildTbsCertWithExtensions() throws CertificateException, IOException
    {
        ASN1Integer serialNumber = new ASN1Integer(-5);

        ASN1ObjectIdentifier sigAlgOID = PKCSObjectIdentifiers.sha1WithRSAEncryption;
        AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(sigAlgOID);

        X500Name issuer = new X500Name("CN=issuer");
        X500Name subject = new X500Name("CN=subject");

        Date now = new Date();
        Date later = new Date(now.getTime() + 1000L * 60 * 60 * 24 * 365);
        Time startDate = new Time(now);
        Time endDate = new Time(later);

        ASN1ObjectIdentifier keyAlgOID = PKCSObjectIdentifiers.rsaEncryption;
        AlgorithmIdentifier keyAlgorithm = new AlgorithmIdentifier(keyAlgOID);
        BigInteger modulus = new BigInteger(
                                            "b62586596b0634775c1dba354599b2d7467a3f820bd1be32a9532428dc5731a378884baa26fc0186c4c6e196ae5a2089fdd5f6e1a78293bdbdfca511d228c9aba48bcdff13d0b2e9d149386abfd9b65ea982351c112ce98f609f85fc33a3bc421c59d98968cf9937ae071aaa8afc6889362c154e01e2da0cff5e64775ef9c5bdd12ac144fe2983bda2b8b3f86343c35c01528a8173799c40a13de68512596831792aeda4ebe5f5c59204790ea040e5e146b21c4d9b825e3d6f1db38ad9d80501937274157d8b26b263070f4fc8272ab77f72ab414dbd4549eb61396e04f3c8f49410cf7bcf224c053c08ba1850d74a0264cf9c594ccc9701b9afe98de194722d",
                                                16);
        BigInteger exponent = BigInteger.valueOf(0x10001);
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPubK =
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(modulus, exponent);
        byte[] keyData = rsaPubK.getEncoded(ASN1Encoding.DER);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(keyAlgorithm, keyData);

        SimpleTBSCertificate tbsCert = new SimpleTBSCertificate();

        tbsCert.setVersionNumber(-3);
        tbsCert.setSerialNumber(serialNumber);
        tbsCert.setSignature(signatureAlgorithm);
        tbsCert.setIssuer(issuer);
        tbsCert.setStartDate(startDate);
        tbsCert.setEndDate(endDate);
        tbsCert.setSubject(subject);
        tbsCert.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        // extensions
        List<SimpleExtension> extensions = new ArrayList<SimpleExtension>();

        SimpleExtension authorityKeyIdentifierExt = new SimpleExtension(Extension.authorityKeyIdentifier);
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier("AuthorityKeyIdentifier".getBytes());
        authorityKeyIdentifierExt.setExtnValueFromObject(authorityKeyIdentifier);
        extensions.add(authorityKeyIdentifierExt);

        SimpleExtension subjectKeyIdentifierExt = new SimpleExtension(Extension.subjectKeyIdentifier);
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier("SubjectKeyIdentifier".getBytes());
        subjectKeyIdentifierExt.setExtnValueFromObject(subjectKeyIdentifier);
        extensions.add(subjectKeyIdentifierExt);

        SimpleExtension keyUsageExt = new SimpleExtension(Extension.keyUsage);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
        keyUsageExt.setExtnValueFromObject(keyUsage);
        extensions.add(keyUsageExt);

        // SimpleExtension certificatePoliciesExt = new SimpleExtension(Extension.certificatePolicies);
        // extensions.add(certificatePoliciesExt);

        // SimpleExtension policyMappingsExt = new SimpleExtension(Extension.policyMappings);
        // extensions.add(policyMappingsExt);

        // SimpleExtension subjectAlternativeNameExt = new SimpleExtension(Extension.subjectAlternativeName);
        // extensions.add(subjectAlternativeNameExt);

        // SimpleExtension issuerAlternativeNameExt = new SimpleExtension(Extension.issuerAlternativeName);
        // extensions.add(issuerAlternativeNameExt);

        // SimpleExtension subjectDirectoryAttributesExt = new SimpleExtension(Extension.subjectDirectoryAttributes);
        // SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes();
        // subjectDirectoryAttributesExt.setExtnValueFromObject(subjectDirectoryAttributes);
        // extensions.add(subjectDirectoryAttributesExt);

        SimpleExtension basicConstraintsExt = new SimpleExtension(Extension.basicConstraints);
        BasicConstraints basicConstraints = new BasicConstraints(3);
        basicConstraintsExt.setExtnValueFromObject(basicConstraints);
        extensions.add(basicConstraintsExt);

        // SimpleExtension nameConstraintsExt = new SimpleExtension(Extension.nameConstraints);
        // extensions.add(nameConstraintsExt);

        SimpleExtension policyConstraintsExt = new SimpleExtension(Extension.policyConstraints);
        PolicyConstraints policyConstraints = new PolicyConstraints(BigInteger.valueOf(10), BigInteger.valueOf(20));
        policyConstraintsExt.setExtnValueFromObject(policyConstraints);
        extensions.add(policyConstraintsExt);

        SimpleExtension extendedKeyUsageExt = new SimpleExtension(Extension.extendedKeyUsage);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
        extendedKeyUsageExt.setExtnValueFromObject(extendedKeyUsage);
        extensions.add(extendedKeyUsageExt);

        // SimpleExtension cRLDistributionPointsExt = new SimpleExtension(Extension.cRLDistributionPoints);
        // extensions.add(cRLDistributionPointsExt);

        // SimpleExtension inhibitAnyPolicyExt = new SimpleExtension(Extension.inhibitAnyPolicy);
        // extensions.add(inhibitAnyPolicyExt);

        // SimpleExtension freshestCRLExt = new SimpleExtension(Extension.freshestCRL);
        // extensions.add(freshestCRLExt);

        // SimpleExtension authorityInfoAccessExt = new SimpleExtension(Extension.authorityInfoAccess);
        // extensions.add(authorityInfoAccessExt);

        // SimpleExtension subjectInfoAccessExt = new SimpleExtension(Extension.subjectInfoAccess);
        // extensions.add(subjectInfoAccessExt);

        // deprecated
        // SimpleExtension privateKeyUsagePeriodExt = new SimpleExtension(Extension.privateKeyUsagePeriod);
        // extensions.add(privateKeyUsagePeriodExt);

        // CRL extension
        SimpleExtension cRLNumberExt = new SimpleExtension(Extension.cRLNumber);
        CRLNumber crlNumber = new CRLNumber(BigInteger.valueOf(100));
        cRLNumberExt.setExtnValueFromObject(crlNumber);
        extensions.add(cRLNumberExt);

        // CRL extension
        SimpleExtension issuingDistributionPointExt = new SimpleExtension(Extension.issuingDistributionPoint);
        IssuingDistributionPoint issuingDistributionPoint =
            new IssuingDistributionPoint(null, true, true, null, true, true);
        issuingDistributionPointExt.setExtnValueFromObject(issuingDistributionPoint);
        extensions.add(issuingDistributionPointExt);

        // SimpleExtension reasonCodeExt = new SimpleExtension(Extension.reasonCode);
        // extensions.add(reasonCodeExt);

        // SimpleExtension instructionCodeExt = new SimpleExtension(Extension.instructionCode);
        // extensions.add(instructionCodeExt);

        // SimpleExtension invalidityDateExt = new SimpleExtension(Extension.invalidityDate);
        // extensions.add(invalidityDateExt);

        // SimpleExtension deltaCRLIndicatorExt = new SimpleExtension(Extension.deltaCRLIndicator);
        // extensions.add(deltaCRLIndicatorExt);

        // CRL entry extension
        // SimpleExtension certificateIssuerExt = new SimpleExtension(Extension.certificateIssuer);
        // extensions.add(certificateIssuerExt);

        // SimpleExtension biometricInfoExt = new SimpleExtension(Extension.biometricInfo);
        // extensions.add(biometricInfoExt);

        // SimpleExtension qCStatementsExt = new SimpleExtension(Extension.qCStatements);
        // extensions.add(qCStatementsExt);

        // SimpleExtension logoTypeExt = new SimpleExtension(Extension.logoType);
        // extensions.add(logoTypeExt);

        tbsCert.setExtensions(extensions);

        logger.debug("tbsCert: {}", ASN1Dump.dumpAsString(tbsCert, true));
    }

}
