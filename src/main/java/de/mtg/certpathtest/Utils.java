
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.sound.midi.SysexMessage;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.security.asn1.x509.cert.SimpleCertificate;
import de.mtg.security.asn1.x509.cert.SimpleTBSCertificate;
import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.tr03124.TestCase;

public class Utils
{
    private static Logger logger = LoggerFactory.getLogger(Utils.class);
    private static Marker fatalMarker = MarkerFactory.getMarker("FATAL");

    public static void exitProgramm(String message)
    {
        logger.error(fatalMarker, message + " Please correct this error.");
        logger.info("Program is exiting.");
        MDC.clear();
        System.exit(0);
    }

    public static void logError(String description)
    {
        logger.error(description);
        ObjectCache objectCache = ObjectCache.getInstance();
        objectCache.addError(description);
    }

    public static GeneralName createGeneralName(String type, String value)
    {

        GeneralName generalName = null;

        if ("rfc822Name".equalsIgnoreCase(type))
        {
            DERIA5String rfc822Name = new DERIA5String(value);
            generalName = new GeneralName(GeneralName.rfc822Name, rfc822Name);
        }
        else if ("dNSName".equalsIgnoreCase(type))
        {
            DERIA5String dNSName = new DERIA5String(value);
            generalName = new GeneralName(GeneralName.dNSName, dNSName);
        }
        else if ("directoryName".equalsIgnoreCase(type))
        {
            X500Name directoryName = new X500Name(value);
            generalName = new GeneralName(GeneralName.directoryName, directoryName);
        }
        else if ("uniformResourceIdentifier".equalsIgnoreCase(type))
        {
            DERIA5String uri = new DERIA5String(value);
            generalName = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        }
        else if ("iPAddress".equalsIgnoreCase(type))
        {
            generalName = new GeneralName(GeneralName.iPAddress, value);
        }
        else if ("registeredID".equalsIgnoreCase(type))
        {
            ASN1ObjectIdentifier registeredID = new ASN1ObjectIdentifier(value);
            generalName = new GeneralName(GeneralName.registeredID, registeredID);
        }

        return generalName;
    }

    public static Date convertValue(String value)
    {

        value = value.trim();

        int difference = Integer.parseInt(value.substring(0, value.length() - 1));

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);

        int occurence = value.indexOf("H");
        if (occurence != -1)
        {
            calendar.add(Calendar.HOUR, difference);
        }
        occurence = value.indexOf("D");
        if (occurence != -1)
        {
            calendar.add(Calendar.DATE, difference);
        }
        occurence = value.indexOf("M");
        if (occurence != -1)
        {
            calendar.add(Calendar.MONTH, difference);
        }
        occurence = value.indexOf("Y");
        if (occurence != -1)
        {
            calendar.add(Calendar.YEAR, difference);
        }

        return calendar.getTime();
    }

    public static Time convertValue(String value, String encoding)
    {

        Date dateValue = Utils.convertValue(value);

        Time time = null;

        if (encoding != null)
        {

            if ("UTC".equalsIgnoreCase(encoding.trim()))
            {
                ASN1UTCTime utcTime = new ASN1UTCTime(dateValue);
                time = new Time(utcTime);
            }
            else if ("GEN".equalsIgnoreCase(encoding.trim()))
            {
                ASN1GeneralizedTime generalizedTime = new ASN1GeneralizedTime(dateValue);
                time = new Time(generalizedTime);
            }
        }
        else
        {
            time = new Time(dateValue);
        }

        return time;

    }

    public static byte[] convertBitString(String bitstring)
    {

        int length = bitstring.length();

        int numberOfLoops = (int) Math.floor((bitstring.length() - 1) / 8);
        byte[] returnValue = new byte[numberOfLoops + 1];

        if (numberOfLoops == 0)
        {
            returnValue[0] = oneByteStringToByte(bitstring);
            return returnValue;
        }

        int loopStart = length - (numberOfLoops * 8);

        String firstByte = bitstring.substring(0, loopStart);

        returnValue[0] = oneByteStringToByte(firstByte);

        for (int i = 0; i < numberOfLoops; i++)
        {

            int start = loopStart + (i * 8);
            int end = loopStart + (i + 1) * 8;

            String substring = bitstring.substring(start, end);

            BigInteger bigInteger = new BigInteger(substring, 2);
            int tmp = bigInteger.intValue() & 0xFF;
            returnValue[i + 1] = (byte) tmp;
        }

        return returnValue;
    }

    private static byte oneByteStringToByte(String bitstring)
    {
        BigInteger bigInteger = new BigInteger(bitstring, 2);
        int returnValue = bigInteger.intValue() & 0xFF;
        return (byte) returnValue;
    }

    public static TestCase extractTestCase(File testCaseFile) throws IOException
    {
        TestCase testCase = new TestCase();

        try
        {
            JAXBContext jaxb = JAXBContext.newInstance(testCase.getClass().getPackage().getName());
            Unmarshaller unmarshaller = jaxb.createUnmarshaller();
            testCase = (TestCase) unmarshaller.unmarshal(testCaseFile);
        }
        catch (JAXBException e)
        {
            Utils.logError("Could not parse XML file '"+testCaseFile.getName()+"'.");
            throw new IOException(e);
        }

        return testCase;
    }

    public static byte[] getRandomByteArray(byte[] input, int percent)
    {

        int size = input.length;

        int numberOfRandomBytes = (int) Math.ceil((size * percent) / 100);

        List<Integer> bytesToChange = new ArrayList<Integer>();

        Random random = new Random();

        while (numberOfRandomBytes > -1)
        {
            Integer index = random.nextInt(size);

            boolean exists = bytesToChange.contains(index);

            if (exists)
            {
                continue;
            }
            else
            {
                bytesToChange.add(index);
            }

            numberOfRandomBytes -= 1;
        }

        byte[] returnValue = new byte[size];
        System.arraycopy(input, 0, returnValue, 0, size);

        for (Integer index : bytesToChange)
        {
            returnValue[index] = (byte) random.nextInt();
        }

        return returnValue;

    }

    public static String getTrustAnchorCertificateID(PKIObjects pkiObjects) throws IOException
    {
        return getCertificateIdOfType(pkiObjects, true);
    }

    public static String getTargetCertificateCertificateID(PKIObjects pkiObjects) throws IOException
    {
        return getCertificateIdOfType(pkiObjects, false);
    }

    private static String getCertificateIdOfType(PKIObjects pkiObjects, boolean isTrustAnchor) throws IOException
    {

        if (pkiObjects == null)
        {
            String message = "Empty PKI Objects. Cannot check for trust anchor or target certificate.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        ArrayList<Certificate> certificates = pkiObjects.getCertificates();

        for (Certificate certificate : certificates)
        {
            String type = certificate.getType();

            if (type != null && type.equalsIgnoreCase("TA") && isTrustAnchor)
            {
                return certificate.getId();
            }

            if (type != null && type.equalsIgnoreCase("TC") && !isTrustAnchor)
            {
                return certificate.getId();
            }

        }

        return null;
    }

    public static int getNumberOfCertificates(PKIObjects pkiObjects)
    {
        return pkiObjects.getCertificates().size();
    }

    private static ArrayList<String> sortCertificates(PKIObjects pkiObjects, boolean fromTA)
                    throws IOException, JAXBException
    {
        ArrayList<String> ids = new ArrayList<String>();
        String targetCertificateId = Utils.getTargetCertificateCertificateID(pkiObjects);
        ids.add(targetCertificateId);

        ArrayList<Certificate> certificates = pkiObjects.getCertificates();

        ArrayList<Certificate> certificatesCopy = new ArrayList<Certificate>();

        for (Certificate certificate : certificates)
        {
            certificatesCopy.add(certificate);
        }

        ObjectCache objectCache = ObjectCache.getInstance();

        String workingId = targetCertificateId;
        String tmpId = targetCertificateId;

        // just in case, to avoid infinite loop
        int counter = 0;
        while (true)
        {
            tmpId = workingId;
            workingId = objectCache.getIssuerId(workingId);
            if (workingId == null)
            {
                break;
            }
            if (workingId.equalsIgnoreCase(tmpId))
            {
                break;
            }
            ids.add(workingId);
            counter += 1;
            if (counter > 500)
            {
                String message =
                    "Could not build information about the chaining of certificates. Please correct the PKI objects or reduce the number of certificates below 500.";
                logger.warn(message);
            }
        }

        int size = ids.size();

        // Remove duplicate (usually) self-signed certificates.
        if (size > 2)
        {

            byte[] lastCertificate = objectCache.getRawCertificate(ids.get(size - 1));
            byte[] secondToLastCertificate = objectCache.getRawCertificate(ids.get(size - 2));

            if (Arrays.equals(lastCertificate, secondToLastCertificate))
            {
                ids.remove(size - 1);
            }
        }

        // START algorithm to exchange the ids with ids only located in this test case PKIObjects (because in the
        // original list the references are found).
        ArrayList<String> idsCopy = new ArrayList<String>();

        for (String id : ids)
        {
            idsCopy.add(id);
        }

        Hashtable<String, String> mappingTable = new Hashtable<String, String>();

        for (Certificate certificate : certificates)
        {

            String testCaseCertificateId = certificate.getId().trim();

            boolean found = false;

            for (String id : idsCopy)
            {
                if (id.equalsIgnoreCase(testCaseCertificateId))
                {
                    // this id can stay in the list, because it is a certificate specified in this pkiObjects
                    found = true;
                    mappingTable.put(id, testCaseCertificateId);
                }
            }

            if (!found)
            {

                byte[] testCaseRawCertificate = objectCache.getRawCertificate(testCaseCertificateId);

                for (String id : idsCopy)
                {

                    byte[] tmpRawCertificate = objectCache.getRawCertificate(id);

                    if (Arrays.equals(tmpRawCertificate, testCaseRawCertificate))
                    {
                        // this certificate is binary identical
                        found = true;
                        mappingTable.put(id, testCaseCertificateId);
                    }
                }
            }

        }

        if (mappingTable.size() != ids.size())
        {
            Utils.logError("Could not create information about the certification path.");
        }

        ArrayList<String> returnList = new ArrayList<String>();
        // STOP

        for (String id : ids)
        {
            returnList.add(mappingTable.get(id));
        }

        if (fromTA)
        {
            Collections.reverse(returnList);
        }

        return returnList;
    }

    public static ArrayList<String> sortCertificatesFromTCToTA(PKIObjects pkiObjects) throws IOException, JAXBException
    {
        return sortCertificates(pkiObjects, false);
    }

    public static ArrayList<String> sortCertificatesFromTAToTC(PKIObjects pkiObjects) throws IOException, JAXBException
    {
        return sortCertificates(pkiObjects, true);
    }

    public static boolean hasReference(TestCase testCase)
    {

        boolean hasReference = false;

        PKIObjects pkiObjects = Utils.getPKIObjects(testCase);

        List<Certificate> certificates = pkiObjects.getCertificates();

        if (certificates != null)
        {
            for (Certificate certificate : certificates)
            {
                String refId = certificate.getRefid();

                if (refId != null && !refId.isEmpty())
                {
                    return true;
                }

            }
        }
        return hasReference;
    }

    public static boolean hasReference(Certificate certificate)
    {

        boolean hasReference = false;
        String refId = certificate.getRefid();

        if (refId != null && !refId.isEmpty())
        {
            hasReference = true;
        }

        return hasReference;
    }

    public static boolean hasOverwrite(Certificate certificate)
    {

        String overwrite = certificate.getOverwrite();

        if (overwrite != null && !overwrite.isEmpty())
        {
            overwrite = overwrite.trim();
            if ("false".equalsIgnoreCase(overwrite))
            {
                return false;
            }
            else
            {
                return true;
            }

        }

        return false;
    }

    public static List<String> getIdOfReferencedCertificates(TestCase testCase)
    {
        PKIObjects pkiObjects = Utils.getPKIObjects(testCase);

        ArrayList<Certificate> certificates = pkiObjects.getCertificates();

        List<String> referenceIds = new ArrayList<String>();

        if (certificates != null)
        {
            for (Certificate certificate : certificates)
            {
                String refId = certificate.getRefid();

                if (refId != null && !refId.isEmpty())
                {
                    referenceIds.add(refId);
                }
            }
        }
        return referenceIds;
    }

    /**
     *
     * Returns the id of this test case to uniquely identify a test case. This can be used for storing the test cases
     * but also reading them from the cache. If the id is not present or is an empty string then this method returns
     * null.
     *
     * @param testCase the test case whose id needs to be extracted.
     * @return the id of this testCase or null if this testCase is null or the id is not present or is an empty string.
     */
    public static String getTestCaseId(TestCase testCase)
    {

        if (testCase == null)
        {
            return null;
        }

        String id = testCase.getId();

        if (id == null || id.isEmpty())
        {
            return null;
        }

        return id;
    }

    public static String getTestCaseProfile(TestCase testCase)
    {

        if (testCase == null)
        {
            return null;
        }

        List<String> profiles = testCase.getProfile();

        if (profiles == null || profiles.isEmpty())
        {
            return null;
        }

        if (profiles.size() != 1)
        {
            Utils.exitProgramm("Test case with id '" + Utils.getTestCaseId(testCase)
                + "' has more than one profile. Only one profile is supported.");
        }

        return profiles.get(0);
    }

    public static String getTestCaseExpectedResult(TestCase testCase)
    {
        String expectedResult = null;
        if (testCase.getTestStep() != null && testCase.getTestStep().size() > 0 && testCase.getTestStep().get(0) != null
            && testCase.getTestStep().get(0).getExpectedResult() != null
            && testCase.getTestStep().get(0).getExpectedResult().get(0) != null
            && testCase.getTestStep().get(0).getExpectedResult().get(0).getText() != null
            && testCase.getTestStep().get(0).getExpectedResult().get(0).getText().getContent() != null
            && testCase.getTestStep().get(0).getExpectedResult().get(0).getText().getContent().get(0) != null)
        {
            expectedResult =
                (String) testCase.getTestStep().get(0).getExpectedResult().get(0).getText().getContent().get(0);
        }
        return expectedResult;
    }

    public static String getTestCaseSeverity(TestCase testCase)
    {
        String severity = null;

        if (testCase.getTestStep() != null && testCase.getTestStep().size() > 0 && testCase.getTestStep().get(0) != null
            && testCase.getTestStep().get(0).getSeverity() != null
            && testCase.getTestStep().get(0).getSeverity().value() != null)
        {
            severity = (String) testCase.getTestStep().get(0).getSeverity().value();
        }
        return severity;
    }

    public static String getTestCasePurpose(TestCase testCase)
    {
        String purpose = null;

        if (testCase.getPurpose() != null && testCase.getPurpose().getContent() != null
            && testCase.getPurpose().getContent().get(0) != null)
        {
            purpose = (String) testCase.getPurpose().getContent().get(0);
        }
        return purpose;
    }

    /**
     *
     * Returns the id of this crl to uniquely identify a CRL. This can be used for storing CRLs but also reading them
     * from the cache. If the id is not present or is an empty string then this method returns null.
     *
     * @param crl the CRL whose id needs to be extracted.
     * @return the id of this crl or null if this crl is null or its id is not present or is an empty string.
     */
    public static String getCRLId(CRL crl)
    {

        if (crl == null)
        {
            return null;
        }

        String id = crl.getId();

        if (id == null || id.isEmpty())
        {
            return null;
        }

        return id;
    }

    /**
     *
     * Returns the id of this certificate to uniquely identify a certificate. This can be used for storing certificates
     * but also reading them from the cache. If the id is not present or is an empty string then this method returns
     * null.
     *
     * @param certificate the certificate whose id needs to be extracted.
     * @return the id of this certificate or null if this certificate is null or the id is not present or is an empty
     *         string.
     */
    public static String getCertificateId(Certificate certificate)
    {

        if (certificate == null)
        {
            return null;
        }

        String id = certificate.getId();

        if (id == null || id.isEmpty())
        {
            return null;
        }

        return id;
    }

    public static PKIObjects getPKIObjects(TestCase testCase)
    {
        String testCaseId = Utils.getTestCaseId(testCase);
        ObjectCache objectCache = ObjectCache.getInstance();
        return objectCache.getPKIobjectsFromTestCase(testCaseId);
    }

    public static X500Name getAsPrintableStringName(String value)
    {

        X500Name sourceX500Name = new X500Name(value);

        RDN[] sourceRDNs = sourceX500Name.getRDNs();

        RDN[] targetRDNs = new RDN[sourceRDNs.length];

        int counter = 0;
        for (RDN sourceRDN : sourceRDNs)
        {
            AttributeTypeAndValue ava =
                new AttributeTypeAndValue(sourceRDN.getFirst().getType(), new DERPrintableString(
                                                                                                 sourceRDN.getFirst()
                                                                                                          .getValue()
                                                                                                          .toString()));
            targetRDNs[counter] = new RDN(ava);
            counter = +1;
        }

        X500Name targetX500Name = new X500Name(targetRDNs);
        return targetX500Name;
    }

    public static byte[] exportPKCS8(PrivateKey privateKey)
    {
        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN PRIVATE KEY-----");
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append(encodePEM(keyspec.getEncoded()));
        stringBuilder.append("-----END PRIVATE KEY-----");
        return stringBuilder.toString().getBytes();
    }

    public static byte[] exportPEMCertificate(byte[] encodedCertificate)
    {
        return encodeCertificatePEM(encodedCertificate).getBytes();
    }

    public static String encodeCertificatePEM(byte[] encodedCertificate)
    {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----");
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append(encodePEM(encodedCertificate));
        stringBuilder.append("-----END CERTIFICATE-----");
        return stringBuilder.toString();
    }

    public static byte[] exportPEMCRL(byte[] encodedCRL)
    {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN X509 CRL-----");
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append(encodePEM(encodedCRL));
        stringBuilder.append("-----END X509 CRL-----");
        return stringBuilder.toString().getBytes();
    }

    public static String prettifyCMS(String cms)
    {

        int length = cms.length();
        int numberOfLoops = (int) Math.floor((cms.length() - 1) / 76);

        StringBuilder stringBuilder = new StringBuilder();

        if (numberOfLoops == 0)
        {
            stringBuilder.append(cms);
        }
        else
        {

            int start = 0;
            int end = 0;

            for (int i = 0; i < numberOfLoops; i++)
            {
                start = (i * 76);
                end = (i + 1) * 76;
                stringBuilder.append(cms.substring(start, end));
                stringBuilder.append(System.getProperty("line.separator"));
            }

            if (end < length)
            {
                stringBuilder.append(cms.substring(end, length));
                stringBuilder.append(System.getProperty("line.separator"));
            }
        }
        return stringBuilder.toString();
    }

    public static String encodePEM(byte[] rawData)
    {

        String encoded = new String(Base64.encode(rawData));
        int length = encoded.length();
        int numberOfLoops = (int) Math.floor((encoded.length() - 1) / 64);

        StringBuilder stringBuilder = new StringBuilder();

        if (numberOfLoops == 0)
        {
            stringBuilder.append(encoded);
        }
        else
        {

            int start = 0;
            int end = 0;

            for (int i = 0; i < numberOfLoops; i++)
            {
                start = (i * 64);
                end = (i + 1) * 64;
                stringBuilder.append(encoded.substring(start, end));
                stringBuilder.append(System.getProperty("line.separator"));
            }

            if (end < length)
            {
                stringBuilder.append(encoded.substring(end, length));
                stringBuilder.append(System.getProperty("line.separator"));
            }
        }
        return stringBuilder.toString();
    }

    public static Certificate createCompleteCertificateFromReference(Certificate certificate)
                    throws JAXBException, IOException
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        String refid = certificate.getRefid();

        Certificate sourceCertificate = objectCache.getCertificate(refid);

        if (!Utils.hasReference(sourceCertificate))
        { // this is a certificate with all properties set
            return updateCertificateData(sourceCertificate, certificate);
        }
        else
        { // recursion
            Certificate targetCertificate = Utils.createCompleteCertificateFromReference(sourceCertificate);
            return updateCertificateData(targetCertificate, certificate);
        }

    }

    private static Certificate updateCertificateData(Certificate sourceCertificate, Certificate targetCertificate)
                    throws JAXBException, IOException
    {
        Certificate sourceCertificateCopy = Utils.cloneCertificate(sourceCertificate);

        Optional.ofNullable(targetCertificate.getVerifiedBy())
                .ifPresent(verifiedBy -> sourceCertificateCopy.setVerifiedBy(verifiedBy));

        Optional.ofNullable(targetCertificate.getVersion())
                .ifPresent(version -> sourceCertificateCopy.setVersion(version));

        Optional.ofNullable(targetCertificate.getSerialNumber())
                .ifPresent(serialNumber -> sourceCertificateCopy.setSerialNumber(serialNumber));

        Optional.ofNullable(targetCertificate.getSignature())
                .ifPresent(signature -> sourceCertificateCopy.setSignature(signature));

        Optional.ofNullable(targetCertificate.getIssuerDN())
                .ifPresent(issuerDN -> sourceCertificateCopy.setIssuerDN(issuerDN));

        Optional.ofNullable(targetCertificate.getSubjectDN())
                .ifPresent(subjectDN -> sourceCertificateCopy.setSubjectDN(subjectDN));

        Optional.ofNullable(targetCertificate.getNotBefore())
                .ifPresent(notBefore -> sourceCertificateCopy.setNotBefore(notBefore));

        Optional.ofNullable(targetCertificate.getNotAfter())
                .ifPresent(notAfter -> sourceCertificateCopy.setNotAfter(notAfter));

        Optional.ofNullable(targetCertificate.getPublicKey())
                .ifPresent(publicKey -> sourceCertificateCopy.setPublicKey(publicKey));

        Optional.ofNullable(targetCertificate.getIssuerUniqueID())
                .ifPresent(issuerUniqueId -> sourceCertificateCopy.setIssuerUniqueID(issuerUniqueId));

        Optional.ofNullable(targetCertificate.getSubjectUniqueID())
                .ifPresent(subjectUniqueId -> sourceCertificateCopy.setSubjectUniqueID(subjectUniqueId));

        Optional.ofNullable(targetCertificate.getModification())
                .ifPresent(modification -> sourceCertificateCopy.setModification(modification));

        ArrayList<Extension> targetExtensions = targetCertificate.getExtensions();

        ArrayList<Extension> sourceExtensions = sourceCertificateCopy.getExtensions();

        if (sourceExtensions != null)
        {
            // the source certificate has extensions
            // overwriting the same extensions, except
            // the modification DUPLICATE_EXTENSION is present

            String targetModificationValue =
                Optional.ofNullable(targetCertificate.getModification()).map(mod -> mod.getId()).orElse(null);
            String sourceModificationValue =
                Optional.ofNullable(sourceCertificate.getModification()).map(mod -> mod.getId()).orElse(null);

            Modification targetModification;
            Modification sourceModification;

            boolean duplicateExtensionModification = false;

            if (targetModificationValue != null)
            {
                targetModification = Modification.valueOf(targetModificationValue);
                if (Modification.DUPLICATE_EXTENSION.equals(targetModification))
                {
                    duplicateExtensionModification = true;
                }
            }

            if (sourceModificationValue != null)
            {
                sourceModification = Modification.valueOf(sourceModificationValue);
                if (Modification.DUPLICATE_EXTENSION.equals(sourceModification))
                {
                    duplicateExtensionModification = true;
                }
            }

            if (duplicateExtensionModification)
            { // adding the duplicates
                for (Extension targetExtension : targetExtensions)
                {
                    sourceExtensions.add(targetExtension);
                }

                sourceCertificateCopy.setExtensions(sourceExtensions);
            }
            else
            { // overwriting the existent ones

                ArrayList<Extension> newExtensions = new ArrayList<Extension>();

                // add every target extension...
                for (Extension targetExtension : targetExtensions)
                {

                    newExtensions.add(targetExtension);
                }

                // ... and add any source extension that is not duplicate
                for (Extension sourceExtension : sourceExtensions)
                {

                    boolean matchFound = false;

                    for (Extension newExtension : newExtensions)
                    {
                        if (newExtension.getOid().trim().equalsIgnoreCase(sourceExtension.getOid().trim()))
                        {
                            matchFound = true;
                        }
                    }

                    if (!matchFound)
                    {
                        newExtensions.add(sourceExtension);
                    }
                }

                sourceCertificateCopy.setExtensions(newExtensions);
            }
        }
        else
        { // the source certificate does not have any extensions, setting the target extensions if any present.
            if (targetExtensions != null && !targetExtensions.isEmpty())
            {
                sourceCertificateCopy.setExtensions(targetExtensions);
            }
        }

        sourceCertificateCopy.setId(targetCertificate.getId());

        Optional.ofNullable(targetCertificate.getOverwrite())
                .ifPresent(overwrite -> sourceCertificateCopy.setOverwrite(overwrite));
        Optional.ofNullable(targetCertificate.getRefid()).ifPresent(refId -> sourceCertificateCopy.setRefid(refId));
        Optional.ofNullable(targetCertificate.getType()).ifPresent(type -> sourceCertificateCopy.setType(type));

        return sourceCertificateCopy;
    }

    /**
     *
     * Creates a new copy of this certificate by marshalling the source object and unmarshalling it to a new traget
     * object, therefore it is not a copy of references but copy of the data in the certificate.
     *
     * @param certificate the source certificate.
     * @return a copy of this certificate.
     * @throws JAXBException if an exception during marshalling/unmarshalling occurs.
     * @throws IOException if an exception during marshalling/unmarshalling occurs.
     */
    public static Certificate cloneCertificate(Certificate certificate) throws JAXBException, IOException
    {
        JAXBContext jaxbContext = JAXBContext.newInstance(Certificate.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, "UTF-8");
        marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        marshaller.marshal(certificate, baos);
        baos.flush();
        baos.close();

        byte[] encodedCertificate = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);

        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        Certificate certificateClone = (Certificate) unmarshaller.unmarshal(bais);
        bais.close();

        // // volatile certificate for working on it
        // // setting ID to a dummy id
        // Random random = new Random();
        // certificateClone.setId(certificate.getId());

        return certificateClone;

    }

    public static PKIObjects applyReplacementsOnPKIObjects(PKIObjects pkiObjects) throws JAXBException, IOException
    {

        JAXBContext jaxbContext = JAXBContext.newInstance(PKIObjects.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, "UTF-8");
        marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        StringWriter stringWriter = new StringWriter();
        marshaller.marshal(pkiObjects, stringWriter);
        stringWriter.flush();
        stringWriter.close();
        String pkiObjectsString = stringWriter.toString();

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();
        Hashtable<String, String> replacementProperties = configurationProperties.getReplacementProperties();
        Enumeration<String> keys = replacementProperties.keys();

        while (keys.hasMoreElements())
        {
            String key = keys.nextElement();
            // remove "replace."
            String xmlKey = key.substring(8);
            pkiObjectsString =
                pkiObjectsString.replaceAll(Pattern.quote("${" + xmlKey + "}"), replacementProperties.get(key).trim());
        }

        byte[] pkiObjectsBytes = pkiObjectsString.getBytes();
        ByteArrayInputStream bais = new ByteArrayInputStream(pkiObjectsBytes);

        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        PKIObjects replacedPKIObjects = (PKIObjects) unmarshaller.unmarshal(bais);
        bais.close();

        return replacedPKIObjects;

    }

    /**
     *
     * Writes this certificate on the filesystem in the file with this filename.
     *
     * @param certificate the certificate to export in the filesystem.
     * @param filename the name of the file where this certificate is exported.
     */
    public static void writeCertificateOnDisc(X509Certificate certificate, String filename)
    {
        try
        {
            writeBytesOnDisc(certificate.getEncoded(), filename);
        }
        catch (CertificateEncodingException e)
        {
            Utils.logError("Could not write certificate on disc.");
            logger.debug("", e);
        }
    }

    /**
     *
     * Writes this bytes on the filesystem in the file with this filename.
     *
     * @param bytes the bytes to write in the filesystem.
     * @param filename the name of the file where these bytes are exported.
     */
    public static void writeBytesOnDisc(byte[] bytes, String filename)
    {
        try
        {
            Files.write(Paths.get(filename), bytes);
        }
        catch (IOException e)
        {
            Utils.logError("Could not write bytes on disc.");
            logger.debug("", e);
        }
    }

    public static byte[] calculateBleichenbacherSignature(byte[] toBeSigned, int garbageLength, BigInteger d,
                                                          BigInteger n, String signatureOID)
                    throws NoSuchAlgorithmException
    {

        int numberOfFFs = 0;

        if (n.bitLength() - 10 < 1024 && n.bitLength() + 10 > 1024)
        {
            numberOfFFs = 128;
        }
        else if (n.bitLength() - 10 < 2048 && n.bitLength() + 10 > 2048)
        {
            numberOfFFs = 256;
        }
        else if (n.bitLength() - 10 < 4096 && n.bitLength() + 10 > 4096)
        {
            numberOfFFs = 512;
        }
        else
        {
            throw new IllegalArgumentException("RSA Key Sizes up to 4096 are supported.");
        }

        HashAlgorithm hashAlgorithm = null;

        if ("1.2.840.113549.1.1.5".equalsIgnoreCase(signatureOID))
        {
            hashAlgorithm = HashAlgorithm.SHA1;
        }
        else if ("1.2.840.113549.1.1.14".equalsIgnoreCase(signatureOID))
        {
            hashAlgorithm = HashAlgorithm.SHA224;
        }
        else if ("1.2.840.113549.1.1.11".equalsIgnoreCase(signatureOID))
        {
            hashAlgorithm = HashAlgorithm.SHA256;
        }
        else if ("1.2.840.113549.1.1.12".equalsIgnoreCase(signatureOID))
        {
            hashAlgorithm = HashAlgorithm.SHA384;
        }
        else if ("1.2.840.113549.1.1.13".equalsIgnoreCase(signatureOID))
        {
            hashAlgorithm = HashAlgorithm.SHA512;
        }
        else
        {
            throw new IllegalArgumentException(
                                               "It is not possible to apply the transformation for this algorithm '"
                                                   + signatureOID + "'.");
        }

        ByteArray result = new ByteArray(hashAlgorithm.getDigestInfo());
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm.getName(), new BouncyCastleProvider());
        md.reset();
        md.update(toBeSigned);
        byte[] digest = md.digest();

        result = result.append(digest);

        // usually it should be: (three bytes for 00 01 and the 00 after the FFs
        // ByteArray ps = new ByteArray("FF", (numberOfFFs - result.getLength() - 3));
        // but here:
        ByteArray ps = new ByteArray("FF", (numberOfFFs - result.getLength() - (3 + garbageLength)));

        byte[] garbage = new byte[garbageLength];
        if (garbageLength > 0)
        {
            Random random = new Random();
            random.nextBytes(garbage);
        }

        ByteArray pkcs1encoded = new ByteArray("00:01", ":");
        pkcs1encoded = pkcs1encoded.append(ps.getValue());
        pkcs1encoded = pkcs1encoded.append((byte) 0x00);
        pkcs1encoded = pkcs1encoded.append(result.getValue());
        if (garbageLength > 0)
        {
            pkcs1encoded = pkcs1encoded.append(garbage);
        }

        byte[] plaintext = pkcs1encoded.getValue();

        BigInteger plainToNumber = new BigInteger(1, plaintext);
        BigInteger calculatedSignatureNumber = plainToNumber.modPow(d, n);
        byte[] calculatedSignature = calculatedSignatureNumber.toByteArray();

        byte[] calculatedSignatureOneMore = ByteArray.removeLeadingZeroBytes(calculatedSignature);

        return calculatedSignatureOneMore;

    }

    public static String getDifferentAlgorithm(String algorithm)
    {

        ArrayList<String> algorithms = new ArrayList<String>();

        algorithms.add("1.2.840.113549.1.1.5"); // SHA1withRSA
        algorithms.add("1.2.840.113549.1.1.14"); // SHA224withRSA
        algorithms.add("1.2.840.113549.1.1.11"); // SHA256withRSA
        algorithms.add("1.2.840.113549.1.1.12"); // SHA384withRSA
        algorithms.add("1.2.840.113549.1.1.13"); // SHA512withRSA

        algorithms.remove(algorithm);

        Random random = new Random();
        int index = random.nextInt(algorithms.size());
        return algorithms.get(index);
    }

    public static String readFileContent(String filename) throws IOException
    {
        String content = new String(Files.readAllBytes(Paths.get(filename)));
        return content;
    }

    public static X509Certificate createDummyCertificate(int size) throws IOException, CertificateException
    {

        // our dummy certificate is at least 281 bytes (signature is 1 byte)
        // and up to 65539 can be created without the encodings changing the length significantly
        if (size < 281 || size > 65539)
        {
            throw new IllegalArgumentException(
                                               "Cannot create certificate with less than 281 bytes or more than 65539.");
        }

        String hardcodedPK =
            "30819F300D06092A864886F70D01010105000" + "3818D0030818902818100C7E707BBEFDD66083CF8C781DFB6A3A"
                + "EE0CAD223DB4023309BD318FE2E4860A26555FC8D55C62E1C693"
                + "931EA84BFE117AE4565F0474F53A7CE7F42335E67B08B54790CF"
                + "343712F1E6DC73A9B5AD596B023402229B6E8B02FF24CA0D5AB3"
                + "1FF8C3DE211577C0CDD625387C530AE68C288B84E8F663466E06" + "89293711D153983DD0203010001";

        SimpleCertificate simpleCertificate = new SimpleCertificate();

        AlgorithmIdentifier signatureOID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));

        SimpleTBSCertificate tbsCertificate = new SimpleTBSCertificate();

        ASN1UTCTime notBefore = new ASN1UTCTime(new Date(1502774977000L));
        ASN1UTCTime notAfter = new ASN1UTCTime(new Date(1502776977000L));

        byte[] encodedPublicKey = new ByteArray(hardcodedPK, "").getValue();

        String dn = "CN=Testtool";

        tbsCertificate.setVersion(new ASN1Integer(BigInteger.ONE));
        tbsCertificate.setSerialNumber(new ASN1Integer(BigInteger.TEN));
        tbsCertificate.setSignature(signatureOID);
        tbsCertificate.setIssuer(new X500Name(dn));
        tbsCertificate.setSubject(new X500Name(dn));
        tbsCertificate.setStartDate(new Time(notBefore));
        tbsCertificate.setEndDate(new Time(notAfter));
        tbsCertificate.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(encodedPublicKey));

        int signatureSize = size - 280;

        X509Certificate cert = null;

        while (true)
        {
            byte[] test = new byte[signatureSize];
            Random r = new Random();
            r.nextBytes(test);

            simpleCertificate.setSignatureAlgorithm(signatureOID);
            simpleCertificate.setTbsCertificate(tbsCertificate);
            simpleCertificate.setSignature(test);

            ByteArrayInputStream bais = new ByteArrayInputStream(simpleCertificate.getEncoded());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(bais);
            bais.close();

            int certSize = cert.getEncoded().length;

            if (certSize > size)
            {
                signatureSize -= 1;
            }
            else if (certSize < size)
            {
                // now the encoding of the signature requires one more byte
                // taking this back from the CN
                signatureSize += 1;
                tbsCertificate.setIssuer(new X500Name("CN=Testtoo"));

            }
            else
            {
                break;
            }

        }

        return cert;

    }

    public static void writeZip(String zipFilename, Path path) throws IOException
    {

        ArrayList<String> filenames = new ArrayList<String>();
        PrepareZipVisitor prepareZipVisitor = new PrepareZipVisitor(filenames);
        Files.walkFileTree(path, prepareZipVisitor);

        FileOutputStream fos = new FileOutputStream(zipFilename);
        ZipOutputStream zos = new ZipOutputStream(fos);

        for (String filename : filenames)
        {

            ZipEntry zipEntry = new ZipEntry(filename);
            zos.putNextEntry(zipEntry);

            if (!filename.endsWith("/"))
            {
                byte[] fileContent = Files.readAllBytes(Paths.get(filename));
                zos.write(fileContent);
            }
            zos.closeEntry();
        }

        zos.flush();
        zos.close();
        fos.flush();
        fos.close();

    }

}
