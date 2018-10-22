
package de.mtg.certpathtest.testcase.handlers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.xml.bind.JAXBException;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ByteArray;
import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.TestCase;

/**
 *
 * It is responsible for writing emails on the filesystem and optionally sending emails over an SMTP server.
 *
 */
public class EmailExportHandler extends TestCaseHandler
{

    private static Logger logger = LoggerFactory.getLogger(EmailExportHandler.class);

    private TestCase testCase;

    private static final String SMIME_SUBDIR_NAME = "smime";

    /**
     *
     * Constructs a newly allocated EmailExportHandler object.
     *
     * @param testCase the test case for which emails should be written and optionally be sent.
     */
    public EmailExportHandler(TestCase testCase)
    {
        super(testCase);
        this.testCase = testCase;
    }

    /**
     *
     * Writes email on the filesystem and optionally send them over SMTP.
     *
     * @throws IOException if certificates and/or emails could not be created/parsed/sent.
     * @throws JAXBException if an exception occurs when working on PKI Objects.
     */
    public void execute() throws IOException
    {

        String testCaseId = testCase.getId();
        ObjectCache objectCache = ObjectCache.getInstance();

        String taId = Utils.getTrustAnchorCertificateID(objectCache.getPKIobjectsFromTestCase(testCaseId));
        String tcId = Utils.getTargetCertificateCertificateID(objectCache.getPKIobjectsFromTestCase(testCaseId));

        String outputDirectoryName =
            ConfigurationProperties.getInstance().getProperties()
                                   .getString(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY);

        Path path = Paths.get(outputDirectoryName, testCaseId);

        if (!path.toFile().exists())
        {
            path.toFile().mkdirs();
        }

        Path pathsOutputPath = Paths.get(outputDirectoryName, testCaseId, SMIME_SUBDIR_NAME);

        if (!pathsOutputPath.toFile().exists())
        {
            pathsOutputPath.toFile().mkdirs();
        }

        PKIObjects pkiObjects = objectCache.getPKIobjectsFromTestCase(testCaseId);

        int size = Utils.getNumberOfCertificates(pkiObjects);

        ArrayList<String> issuedBy = Utils.sortCertificatesFromTAToTC(pkiObjects);

        if (size != issuedBy.size()) {

            issuedBy = new ArrayList<>();

            if (Utils.hasExplicitPath(pkiObjects))
            {
                de.mtg.certpathtest.pkiobjects.Path pkiObjectsPath = pkiObjects.getPath();
                String pathValue = pkiObjectsPath.getValue();
                StringTokenizer tokenizer = new StringTokenizer(pathValue, ",");

                while (tokenizer.hasMoreTokens())
                {
                    String id = tokenizer.nextToken().trim();
                    issuedBy.add(id);
                }
            }
        }

        if (CollectionUtils.isNotEmpty(issuedBy))
        {

            try
            {
                byte[] encodedSMIME = createSMIME(testCaseId, issuedBy);
                Files.write(Paths.get(outputDirectoryName, testCaseId, SMIME_SUBDIR_NAME, testCaseId + ".eml"),
                            encodedSMIME);

                ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

                boolean useSMTP =
                    configurationProperties.getProperties().getBoolean(ConfigurationProperties.EMAIL_SMTP_USE);
                String smtpHost =
                    configurationProperties.getProperties().getString(ConfigurationProperties.EMAIL_SMTP_HOST);
                String smtpPort =
                    configurationProperties.getProperties().getString(ConfigurationProperties.EMAIL_SMTP_PORT);

                if (useSMTP)
                {
                    ByteArrayInputStream bais = new ByteArrayInputStream(encodedSMIME);

                    Properties props = new Properties();
                    props.put("mail.smtp.host", smtpHost);
                    props.put("mail.smtp.port", smtpPort);

                    Session session = Session.getInstance(props, null);
                    MimeMessage encryptedMessage = new MimeMessage(session, bais);
                    Transport.send(encryptedMessage);

                    bais.close();
                }
            }
            catch (Exception e)
            {
                Utils.logError("Could not export or send signed email for test case '" + testCaseId + "'.");
                logger.debug("", e);
            }

        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private byte[] createSMIME(String testCaseId, ArrayList<String> certificates) throws OperatorCreationException,
                    MessagingException, SMIMEException, CMSException, IOException, CertificateException
    {

        Hashtable<String, String> certificateReplacements = new Hashtable<>();

        boolean hasReplacements = false;

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String configuredSender =
            configurationProperties.getProperties().getString(ConfigurationProperties.EMAIL_SENDER);
        String configuredRecipient =
            configurationProperties.getProperties().getString(ConfigurationProperties.EMAIL_RECIPIENT);

        if (StringUtils.isEmpty(configuredSender))
        {
            Utils.logError("Configured sender of emails is empty.");
        }
        if (StringUtils.isEmpty(configuredRecipient))
        {
            Utils.logError("Configured recipient of emails is empty.");
        }

        List certList = new ArrayList();

        String targetCertificateId = certificates.get(certificates.size() - 1);

        X509Certificate eeCert = null;

        ObjectCache objectCache = ObjectCache.getInstance();
        byte[] rawCert = objectCache.getRawCertificate(targetCertificateId);
        PrivateKey eePrivateKey = objectCache.getPrivateKey(targetCertificateId);

        try
        {
            ByteArrayInputStream bais = new ByteArrayInputStream(rawCert);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            eeCert = (X509Certificate) cf.generateCertificate(bais);
            bais.close();

            certList.add(eeCert);
        }
        catch (CertificateException e)
        {

            logger.debug("Found certificate that cannot be decoded.");

            hasReplacements = true;

            int size = rawCert.length;

            X509Certificate certificate = Utils.createDummyCertificate(size);

            certificateReplacements.put(ByteArray.toString(certificate.getEncoded()), ByteArray.toString(rawCert));
            eeCert = certificate;
            certList.add(certificate);

        }
        catch (Exception e)
        {
            Utils.logError("Error while handling certificates with wrong encoding. " + e);
            logger.debug("", e);
        }

        // leave root (i=1 and not i=0)
        // leave target certificate (i < certificates.size()-1 and not i < certificates.size())
        for (int i = 1; i < certificates.size() - 1; i++)
        {
            String certificateId = certificates.get(i);
            rawCert = objectCache.getRawCertificate(certificateId);

            try
            {
                ByteArrayInputStream bais = new ByteArrayInputStream(rawCert);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(bais);
                bais.close();
                certList.add(certificate);
            }
            catch (CertificateException e)
            {

                logger.debug("Found certificate '{}' that cannot be decoded.", certificateId);

                hasReplacements = true;

                int size = rawCert.length;

                X509Certificate certificate = Utils.createDummyCertificate(size);

                certificateReplacements.put(ByteArray.toString(certificate.getEncoded()), ByteArray.toString(rawCert));

                certList.add(certificate);

            }
            catch (Exception e)
            {
                Utils.logError("Error while handling certificates with wrong encoding. " + e);
                logger.debug("", e);
            }

        }

        //
        // create a CertStore containing the certificates we want carried
        // in the signature
        //
        Store certs = new JcaCertStore(certList);

        //
        // create some smime capabilities in case someone wants to respond
        //
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        //
        // create the generator for creating an smime/signed message
        //
        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        String configuredSignatureAlgorithm =
            configurationProperties.getProperties().getString(ConfigurationProperties.EMAIL_SMIME_SIGNATURE_ALGORITHM);

        //
        // add a signer to the generator - this specifies we are using SHA1 and
        // adding the smime attributes above to the signed attributes that
        // will be generated as part of the signature. The encryption algorithm
        // used is taken from the key - in this RSA with PKCS1Padding
        //
        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                                                                            .setSignedAttributeGenerator(new AttributeTable(signedAttrs))
                                                                            .build(configuredSignatureAlgorithm,
                                                                                   eePrivateKey, eeCert));

        gen.addCertificates(certs);

        MimeBodyPart mimeBodyPart = new MimeBodyPart();

        mimeBodyPart.setText("Test Case: " + testCaseId);

        MimeMultipart mimeMultipart = gen.generate(mimeBodyPart);

        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address sender = new InternetAddress(configuredSender);
        Address recipient = new InternetAddress(configuredRecipient);

        MimeMessage mimeMessage = new MimeMessage(session);
        mimeMessage.setFrom(sender);
        mimeMessage.setRecipient(Message.RecipientType.TO, recipient);
        mimeMessage.setSubject(testCaseId);
        mimeMessage.setContent(mimeMultipart, mimeMultipart.getContentType());
        mimeMessage.saveChanges();

        SMIMESigned signed = new SMIMESigned(mimeMultipart);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        mimeMessage.writeTo(baos);
        byte[] encodedMessage = baos.toByteArray();
        baos.flush();
        baos.close();

        String smimeMessage = new String(encodedMessage);

        if (hasReplacements)
        {

            String dummyCMS = ByteArray.toString(signed.getEncoded());

            Enumeration<String> keys = certificateReplacements.keys();

            while (keys.hasMoreElements())
            {
                String key = keys.nextElement();

                if (dummyCMS.indexOf(key) == -1)
                {
                    Utils.logError("Could not replace dummy certificate with the correct one. Reference not found.");
                }
                else
                {
                    dummyCMS = dummyCMS.replaceAll(Pattern.quote(key), certificateReplacements.get(key));

                    if (dummyCMS.indexOf(key) != -1)
                    {
                        Utils.logError("Could not replace dummy certificate with the correct one. Reference still found.");
                    }

                    if (dummyCMS.indexOf(certificateReplacements.get(key)) == -1)
                    {
                        Utils.logError("Could not replace dummy certificate with the correct one. Certificate with decoding errors not found.");
                    }
                }
            }

            String startOfCMS = new String(Base64.encode(signed.getEncoded()));
            startOfCMS = startOfCMS.substring(0, 20);

            encodedMessage = exchangeCMS(smimeMessage, startOfCMS,
                                         new String(Base64.encode(new ByteArray(dummyCMS, "").getValue()))).getBytes();

        }

        return encodedMessage;
    }

    private static String exchangeCMS(String smime, String startOfCMS, String newCMS)
    {

        int start = smime.indexOf(startOfCMS);
        int stop = smime.indexOf("------=", smime.indexOf(startOfCMS) + 1);

        StringBuilder sb = new StringBuilder();

        sb.append(smime.substring(0, start));
        sb.append(Utils.prettifyCMS(newCMS));
        sb.append(System.getProperty("line.separator"));
        sb.append(smime.substring(stop));

        return sb.toString();

    }

}
