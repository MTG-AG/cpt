
package de.mtg.certpathtest.testcase.handlers;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Optional;

import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import de.mtg.certpathtest.DuplicateKeyException;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.TestToolCRL;
import de.mtg.certpathtest.TestToolCertificate;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.TestCase;

public class CreateCertificateHandler extends TestCaseHandler
{

    private static Logger logger = LoggerFactory.getLogger(CreateCertificateHandler.class);

    private TestCase testCase;

    public CreateCertificateHandler(TestCase testCase)
    {
        super(testCase);
        this.testCase = testCase;
    }

    public void execute() throws Exception
    {

        String testCaseId = testCase.getId();

        ObjectCache objectCache = ObjectCache.getInstance();

        PKIObjects pkiObjects = objectCache.getPKIobjectsFromTestCase(testCaseId);

        workOnObjects(pkiObjects, testCase);

    }

    private void workOnObjects(PKIObjects pkiObjects, TestCase testCase) throws Exception
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        ArrayList<Certificate> certificates = pkiObjects.getCertificates();
        ArrayList<CRL> crls = pkiObjects.getCRLs();

        int certSize = certificates.size();
        int crlSize = crls.size();

        try
        {
            for (Certificate certificate : certificates)
            {

                String certificateId = certificate.getId();
                MDC.put("CERTIFICATE", certificateId);
                byte[] rawCertificate = null;

                logger.info("Creating certificate.");

                if (Utils.hasReference(certificate) && !Utils.hasOverwrite(certificate))
                {

                    // certificate is a copy

                    String refid = certificate.getRefid();

                    if (refid == null || refid.isEmpty())
                    {
                        Utils.exitProgramm("Certificate with id '" + certificateId
                            + "' needs to be overwritten, but there is no reference cetificate specified.");
                    }

                    if (refid.equalsIgnoreCase(certificateId)) {
                        Utils.exitProgramm("Certificate with id '" + certificateId + "' references itself.");
                    }

                    logger.debug("This certificate is a direct copy of certificate with id '{}'.", refid);
                    logger.debug("Certificate definition: {}.", certificate.toString());

                    rawCertificate = objectCache.getRawCertificate(refid);

                    if (rawCertificate == null) {
                        Utils.exitProgramm("Certificate with id '" + certificateId + "' references certificate with id '" + refid + "' but this certificate does not exist or has not been created.");
                    }

                    if (objectCache.getPrivateKey(refid) == null) {
                        Utils.exitProgramm("Certificate with id '" + certificateId + "' references certificate with id '" + refid + "' but the private key of this certificate does not exist or has not been created.");
                    }

                    if (objectCache.getPublicKey(refid) == null) {
                        Utils.exitProgramm("Certificate with id '" + certificateId + "' references certificate with id '" + refid + "' but the public key of this certificate does not exist or has not been created.");
                    }

                    Certificate completeCertificate = Utils.createCompleteCertificateFromReference(certificate);
                    objectCache.assignIssuerToCertificate(certificateId, completeCertificate.getVerifiedBy());

                    objectCache.addPrivateKey(certificateId, objectCache.getPrivateKey(refid));
                    objectCache.addPublicKey(certificateId, objectCache.getPublicKey(refid));
                }
                else
                { // certificate is newly defined one or is a copy with changes.
                    logger.debug("This certificate is a newly defined one or a copy of another certificate.");
                    rawCertificate = createCertificate(certificate);
                }

                if (Optional.ofNullable(rawCertificate).isPresent())
                {
                    objectCache.addCertificate(certificate.getId(), rawCertificate);
                    logger.info("Successfully created certificate.");
                }
                else
                {
                    Utils.logError("Could not create certificate.");
                }

                MDC.remove("CERTIFICATE");
            }
        }
        finally
        {
            MDC.remove("CERTIFICATE");
        }

        if (certSize > 0)
        {
            logger.info("Successfully created certificate(s) for test case '{}'.", testCase.getId());
        }

        try
        {
            for (CRL crl : crls)
            {

                String crlId = crl.getId();
                MDC.put("CRL", crlId);
                byte[] rawCRL = null;

                logger.info("Creating CRL.");

                rawCRL = createCRL(crl);

                if (Optional.ofNullable(rawCRL).isPresent())
                {
                    objectCache.addCRL(crlId, rawCRL);
                    logger.info("Successfully created CRL.");
                }
                else
                {
                    Utils.logError("Could not create CRL.");
                }

            }
        }
        finally
        {
            MDC.remove("CRL");
        }

        if (crlSize > 0)
        {
            logger.info("Successfully created revocation list(s) for test case '{}'.", testCase.getId());
        }

    }

    private byte[] createCertificate(Certificate certificate) throws Exception
    {

        logger.debug("Creating certificate for original certificate definition {}.", certificate.toString());

        String refid = certificate.getRefid();

        Certificate certificateToWorkOn = null;

        if (refid != null && !refid.isEmpty())
        {

            // overwrite must be set and must be true otherwise there is no need to create a certificate,
            String overwrite = certificate.getOverwrite();

            if (overwrite == null || !("true".equalsIgnoreCase(overwrite.trim())))
            {
                Utils.exitProgramm("Creating certificate with id '" + certificate.getId()
                    + "', but the certificate is not overwriting any other certificate.");
            }

            certificateToWorkOn = Utils.createCompleteCertificateFromReference(certificate);

        }
        else
        {
            certificateToWorkOn = Utils.cloneCertificate(certificate);
        }

        logger.debug("Creating certificate for adjusted certificate definition {}.", certificateToWorkOn.toString());

        TestToolCertificate testToolCertificate = new TestToolCertificate(certificateToWorkOn);
        return testToolCertificate.getEncoded();

    }

    private byte[] createCRL(CRL crl) throws Exception
    {

        logger.debug("CRL:" + crl);
        TestToolCRL testToolCRL = new TestToolCRL(crl);
        return testToolCRL.getEncoded();
    }

}
