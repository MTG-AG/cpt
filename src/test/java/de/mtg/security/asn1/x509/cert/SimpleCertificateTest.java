/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.CertificateCreator;

/**
 * Test of {@link SimpleCertificate}.
 */
public class SimpleCertificateTest
{
    private static Logger logger = LoggerFactory.getLogger(SimpleCertificateTest.class);
    private CertificateCreator certificateCreator;
    private static final Provider BC = new BouncyCastleProvider();

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
    @BeforeEach
    public void setUp() throws Exception
    {
        certificateCreator = CertificateCreator.getInstance();
    }

    /**
     * Tests building a certificate from bytes and components.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void buildAndRebuild() throws IOException, CertificateEncodingException
    {
        buildAndRebuild(certificateCreator.getRootCACertificate());
        buildAndRebuild(certificateCreator.getSubCACertificate());
        buildAndRebuild(certificateCreator.getEeCertificate());
    }

    private void buildAndRebuild(X509Certificate certificate) throws IOException, CertificateEncodingException
    {
        byte[] inCertBytes = certificate.getEncoded();

        SimpleCertificate inCert = SimpleCertificate.getInstance(inCertBytes);

        byte[] certBytes = inCert.getEncoded(ASN1Encoding.DER);
        Assertions.assertArrayEquals(inCertBytes, certBytes);

        SimpleCertificate outCert = new SimpleCertificate();

        outCert.setTbsCertificate(inCert.getTbsCertificate());
        outCert.setSignatureAlgorithm(inCert.getSignatureAlgorithm());
        outCert.setSignature(inCert.getSignature());

        byte[] outCertBytes = outCert.getEncoded(ASN1Encoding.DER);
        Assertions.assertArrayEquals(inCertBytes, outCertBytes);

        logger.debug("outCert: {}", ASN1Dump.dumpAsString(outCert, true));

    }

    /**
     * Checks values.
     *
     * @throws IOException if encoding errors occur.
     * @throws CertificateEncodingException if encoding errors regarding certificates occur.
     */
    @Test
    public void checkValues() throws IOException, CertificateEncodingException
    {
        byte[] certBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(certBytes);

        logger.debug("SignatureAlgorithm: {}", ASN1Dump.dumpAsString(cert.getSignatureAlgorithm(), true));

        String oid = cert.getSigAlgOID();
        logger.debug("oid: {}", oid);
        Assertions.assertEquals("1.2.840.113549.1.1.11", oid);

        byte[] params = cert.getSigAlgParams();
        String paramsHex = Hex.toHexString(params);
        logger.debug("paramsHex: {}", paramsHex);
        logger.debug("SigAlgParams: {}", ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(params), true));
        Assertions.assertArrayEquals(new byte[] {5, 0}, params);
    }

    /**
     * Tests building and verifying a self-signed EC certificate.
     *
     * @throws IOException if encoding errors occur.
     * @throws GeneralSecurityException if errors during cryptographic operations occur.
     */
    @Test
    public void verifyEcSelfSigned() throws IOException, GeneralSecurityException
    {

        byte[] inCertBytes = certificateCreator.getRootCACertificate().getEncoded();

        SimpleCertificate cert = SimpleCertificate.getInstance(inCertBytes);
        logger.debug("cert: {}", ASN1Dump.dumpAsString(cert, true));

        String sigAlgOID = cert.getSigAlgOID();
        byte[] sigBytes = cert.getSignature().getBytes();
        byte[] tbsBytes = cert.getToBeSigned();

        // self-signed
        PublicKey publicKey = cert.getTbsCertificate().getPublicKey();

        Signature verifier = Signature.getInstance(sigAlgOID, BC);
        verifier.initVerify(publicKey);
        verifier.update(tbsBytes);
        boolean verified = verifier.verify(sigBytes);
        Assertions.assertTrue(verified);
    }

}
