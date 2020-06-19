/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.crl;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLException;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.CertificateCreator;

/**
 * Test of {@link SimpleCertificateList} or CRL.
 */
public class SimpleCertificateListTest
{
    private static Logger logger = LoggerFactory.getLogger(SimpleCertificateListTest.class);

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
    @BeforeEach
    public void setUp() throws Exception
    {
        certificateCreator = CertificateCreator.getInstance();
    }

    /**
     * Tests building a CRL from bytes and components.
     *
     * @throws IOException if encoding errors occur.
     * @throws CRLException if encoding errors regarding CRLs occur.
     */
    @Test
    public void buildFromBytesAndComponents() throws IOException, CRLException
    {
        byte[] inCrlBytes = certificateCreator.getCrl().getEncoded();

        SimpleCertificateList inCrl = SimpleCertificateList.getInstance(inCrlBytes);

        byte[] crlBytes = inCrl.getEncoded(ASN1Encoding.DER);
        Assertions.assertArrayEquals(inCrlBytes, crlBytes);

        SimpleCertificateList outCrl = new SimpleCertificateList();

        outCrl.setTbsCertList(inCrl.getTbsCertList());
        outCrl.setSignatureAlgorithm(inCrl.getSignatureAlgorithm());
        outCrl.setSignatureValue(inCrl.getSignatureValue());

        byte[] outCrlBytes = outCrl.getEncoded(ASN1Encoding.DER);
        Assertions.assertArrayEquals(inCrlBytes, outCrlBytes);
    }

    /**
     * Tests building a CRL from bytes and modification.
     *
     * @throws IOException if encoding errors occur.
     * @throws CRLException if encoding errors regarding CRLs occur.
     */
    @Test
    public void buildAndModify() throws IOException, CRLException
    {
        byte[] inCrlBytes = certificateCreator.getCrl().getEncoded();

        SimpleCertificateList inCrl = SimpleCertificateList.getInstance(inCrlBytes);

        byte[] crlBytes = inCrl.getEncoded(ASN1Encoding.DER);
        Assertions.assertArrayEquals(inCrlBytes, crlBytes);

        // clone the CRL (has no common components)
        SimpleCertificateList newCrl = SimpleCertificateList.getInstance(inCrlBytes);

        SimpleTBSCertList tbsCertList = newCrl.getTbsCertList();

        logger.debug("Version: {}", tbsCertList.getVersion());
        logger.debug("Signature: {}", tbsCertList.getSignature());
        logger.debug("Issuer: {}", tbsCertList.getIssuer());
        logger.debug("ThisUpdate: {}", tbsCertList.getThisUpdate());
        logger.debug("NextUpdate: {}", tbsCertList.getNextUpdate());
        logger.debug("RevokedCertificates: {}", tbsCertList.getRevokedCertificates());
        logger.debug("CrlExtensions: {}", tbsCertList.getCrlExtensions());

        List<RevokedCertificate> revokedCerts = tbsCertList.getRevokedCertificates();
        Assertions.assertNotNull(revokedCerts);
        Assertions.assertFalse(revokedCerts.isEmpty());

        RevokedCertificate revokedCert = revokedCerts.get(0);

        logger.debug("UserCertificate: {}", revokedCert.getUserCertificate());
        logger.debug("RevocationDate: {}", revokedCert.getRevocationDate());
        logger.debug("CrlEntryExtensions: {}", revokedCert.getCrlEntryExtensions());

        // delete optionals components
        tbsCertList.setVersion(null);
        tbsCertList.setNextUpdate(null);
        tbsCertList.setRevokedCertificates(null);
        tbsCertList.setCrlExtensions(null);

        // delete signature
        newCrl.setSignatureValue(new byte[0]);

        byte[] shortCrlBytes = newCrl.getEncoded(ASN1Encoding.DER);
        Assertions.assertTrue(shortCrlBytes.length < inCrlBytes.length);

        String inCrlString = ASN1Dump.dumpAsString(inCrl, true);
        String newCrlString = ASN1Dump.dumpAsString(newCrl, true);

        logger.debug("inCrlString: {}", inCrlString);
        logger.debug("newCrlString: {}", newCrlString);
    }

}
