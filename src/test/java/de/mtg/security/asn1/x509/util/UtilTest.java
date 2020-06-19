/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.CertificateCreator;
import de.mtg.security.asn1.x509.cert.SimpleCertificate;
import de.mtg.security.asn1.x509.cert.SimpleTBSCertificate;

/**
 * Test of {@link Util}.
 */
public class UtilTest
{
    private static Logger logger = LoggerFactory.getLogger(UtilTest.class);

    private CertificateCreator certificateCreator;

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp() throws Exception
    {
        certificateCreator = CertificateCreator.getInstance();
    }

    /**
     * Checks public key.
     *
     * @throws IOException if encoding errors occur.
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     */
    @Test
    public void checkPublicKey() throws IOException, GeneralSecurityException
    {
        byte[] certBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(certBytes);
        SimpleTBSCertificate tbsCert = cert.getTbsCertificate();

        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCert.getSubjectPublicKeyInfo();
        String keyOID = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
        DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
        logger.debug("Algorithm OID: {}", keyOID);
        logger.debug("PublicKeyData: {}",
                     ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(publicKeyData.getBytes()), true));
        Assertions.assertEquals(0, publicKeyData.getPadBits());

        // PublicKey publicKey = tbsCert.getPublicKey();
        PublicKey publicKey = Util.buildPublicKey(subjectPublicKeyInfo);
        logger.debug("publicKey: {}", publicKey);
        Assertions.assertEquals("1.2.840.113549.1.1.1", keyOID);
        Assertions.assertTrue(publicKey instanceof java.security.interfaces.RSAPublicKey);

        Assertions.assertArrayEquals(subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER), publicKey.getEncoded());

        SubjectPublicKeyInfo spki = Util.buildSubjectPublicKeyInfo(publicKey);
        Assertions.assertEquals(subjectPublicKeyInfo.getAlgorithm(), spki.getAlgorithm());
        Assertions.assertEquals(publicKeyData, spki.getPublicKeyData());
    }

    /**
     * Checks names.
     *
     * @throws IOException if encoding errors occur.
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     */
    @Test
    public void checkNames() throws IOException, GeneralSecurityException
    {
        byte[] certBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(certBytes);
        SimpleTBSCertificate tbsCert = cert.getTbsCertificate();

        X500Name issuerName = tbsCert.getIssuer();
        X500Principal issuerPrincipal = Util.nameToPrincipal(issuerName);
        logger.debug("issuerName: {}", issuerName);
        logger.debug("issuerPrincipal: {}", issuerPrincipal);
        Assertions.assertNotNull(issuerName);
        Assertions.assertNotNull(issuerPrincipal);
        X500Name iName = Util.principalToName(issuerPrincipal);
        Assertions.assertEquals(issuerName, iName);

        X500Name subjectName = tbsCert.getSubject();
        X500Principal subjectPrincipal = Util.nameToPrincipal(subjectName);
        logger.debug("subjectName: {}", subjectName);
        logger.debug("subjectPrincipal: {}", subjectPrincipal);
        Assertions.assertNotNull(subjectName);
        Assertions.assertNotNull(subjectPrincipal);
        X500Name sName = Util.principalToName(subjectPrincipal);
        Assertions.assertEquals(subjectName, sName);
    }

}
