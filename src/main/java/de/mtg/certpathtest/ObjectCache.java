package de.mtg.certpathtest;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import de.mtg.certpathtest.pkiobjects.CRL;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.OcspResponse;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.tr03124.TestCase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple cache to hold all objects that are produced or are needed while the program runs. It holds certificates,
 * CRLs, test cases, private keys etc. in order to be easily accessible for further use.
 */
public class ObjectCache
{
    private static Logger logger = LoggerFactory.getLogger(ObjectCache.class);

    private static ObjectCache objectCache;

    private ConcurrentHashMap<String, Certificate> certificates = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, TestCase> testCases = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, CRL> crls = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, PrivateKey> privateKeys = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, byte[]> publicKeys = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, byte[]> rawCertificates = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, byte[]> rawCrls = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, PKIObjects> testCasePKIObjects = new ConcurrentHashMap<>();

    private ConcurrentHashMap<String, OcspResponse> ocspResponses = new ConcurrentHashMap<>();

    private ConcurrentHashMap<String, byte[]> rawOcspResponses = new ConcurrentHashMap<>();

    // TestCase mapping to Certificate
    private ConcurrentHashMap<String, List<String>> testCaseToCertificateMap = new ConcurrentHashMap<>();

    // TestCase mapping to CRL
    private ConcurrentHashMap<String, List<String>> testCaseToCRLMap = new ConcurrentHashMap<>();

    // TestCase mapping to OCSP
    private ConcurrentHashMap<String, List<String>> testCaseToOCSPMap = new ConcurrentHashMap<>();

    // Certificate mapping to TestCase
    private ConcurrentHashMap<String, String> certificateToTestCaseMap = new ConcurrentHashMap<>();

    // CRL mapping to TestCase
    private ConcurrentHashMap<String, String> crlToTestCaseMap = new ConcurrentHashMap<>();

    // OCSP Response mapping to TestCase
    private ConcurrentHashMap<String, String> ocspResponseToTestCaseMap = new ConcurrentHashMap<>();

    // certificate in key is signed by certificate in value
    private ConcurrentHashMap<String, String> certificateIssuerMap = new ConcurrentHashMap<>();

    // mapping of HTTP CRL DPs to CRLs
    private ConcurrentHashMap<String, String> httpCRLDPs = new ConcurrentHashMap<>();

    // mapping of LDAP CRL DPs to CRLs
    private ConcurrentHashMap<String, String> ldapCRLDPs = new ConcurrentHashMap<>();

    // mapping of HTTP OCSP AIA to OCSP Responses
    private ConcurrentHashMap<String, String> ocspAIAs = new ConcurrentHashMap<>();

    private List<String> errors = new ArrayList<>();

    private ConcurrentHashMap<String, String> serialNumbers = new ConcurrentHashMap<>();

    private String archiveTimestamp = new String();

    private List<String> ldapEntries = new ArrayList<>();

    private ConcurrentHashMap<String, Certificate> resolvedCertificates = new ConcurrentHashMap<>();


    private ObjectCache()
    {

    }

    public void addError(String description)
    {
        errors.add(description);
    }

    public List<String> getErrors()
    {
        return errors;
    }

    public void addLDAPEntry(String dn)
    {
        ldapEntries.add(dn);
    }

    public List<String> getLDAPEntries()
    {
        return ldapEntries;
    }

    public String getArchiveTimestamp()
    {
        return archiveTimestamp;
    }

    public void setArchiveTimestamp(String archiveTimestamp)
    {
        this.archiveTimestamp = archiveTimestamp;
    }

    public void addSerialNumber(String serialNumber, String certificateId)
    {

        String previousId = serialNumbers.get(serialNumber);

        if (previousId != null)
        {
            Utils.exitProgramm("Certificate with id '" + previousId
                                       + "' has already been created with the same serial number '" + serialNumber +
                                       "'.");
        }
        else
        {
            serialNumbers.put(serialNumber, certificateId);
        }

    }

    /**
     * Stores a certificate on the temporary cache only if it is not already present. It can be used to hold a reference
     * to a certificate in order to access it later, for example when another certificate is created using this
     * certificate as a template.
     *
     * @param certificate the certificate described in XML.
     *
     * @throws DuplicateKeyException if a certificate with the same id is already present.
     * @throws IllegalArgumentException if this certificate has a null or empty empty id.
     */
    public void addCertificate(Certificate certificate) throws DuplicateKeyException
    {

        if (certificate == null)
        {
            String message = "Certificate is null. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = certificate.getId();

        if (key == null || key.isEmpty())
        {
            String message = "Certificate has an empty id. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = certificates.put(key, certificate);

        if (previous != null)
        {
            String message = "Certificate with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    public void addResolvedCertificate(Certificate certificate) throws DuplicateKeyException
    {

        if (certificate == null)
        {
            String message = "Certificate is null. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = certificate.getId();

        if (key == null || key.isEmpty())
        {
            String message = "Certificate has an empty id. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = resolvedCertificates.put(key, certificate);

        if (previous != null)
        {
            String message = "Certificate with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    /**
     * Stores a CRL on the temporary cache only if it is not already present. It can be used to hold a reference to a
     * CRL in order to access it later.
     *
     * @param crl the CRL described in XML.
     *
     * @throws DuplicateKeyException if a CRL with the same id is already present.
     * @throws IllegalArgumentException if this CRL has a null or empty empty id.
     */
    public void addCRL(CRL crl) throws DuplicateKeyException
    {

        if (crl == null)
        {
            String message = "CRL is null. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = crl.getId();

        if (key == null || key.isEmpty())
        {
            String message = "CRL has an empty id. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = crls.put(key, crl);

        if (previous != null)
        {
            String message = "CRL with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    /**
     * Stores an OCSP Response on the temporary cache only if it is not already present. It can be used to hold a
     * reference to an OCSP response in order to access it later.
     *
     * @param ocspResponse the ocspResponse described in XML.
     *
     * @throws DuplicateKeyException if an OCSP response with the same id is already present.
     * @throws IllegalArgumentException if this ccspResponse has a null or empty empty id.
     */
    public void addOCSPResponse(OcspResponse ocspResponse) throws DuplicateKeyException
    {

        if (ocspResponse == null)
        {
            String message = "OCSP response is null. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = ocspResponse.getId();

        if (key == null || key.isEmpty())
        {
            String message = "OCSP response has an empty id. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = ocspResponses.put(key, ocspResponse);

        if (previous != null)
        {
            String message = "OCSP response with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    /**
     * Stores a test case on the temporary cache only if it is not already present. It can be used to hold a reference
     * to a test case in order to access it later. The filename where the test case is specified can be used as an
     * identifier for this test case. Test cases are specified in XML and are usually stored in a file (see also
     * TR-03124-2).
     *
     * @param testCase the test case described in XML.
     * @param id the id of the test case corresponding to this testCase. The name of the file containing the XML
     * description of a test case can be used as an identifier.
     *
     * @throws DuplicateKeyException if a test case with the same filename is already present.
     * @throws IllegalArgumentException if this id is null or empty.
     */
    public void addTestCase(TestCase testCase, String id) throws DuplicateKeyException
    {

        if (testCase == null)
        {
            String message = "Test case is null. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = testCase.getId();

        if (id == null || id.isEmpty())
        {
            String message = "Test case has an empty id. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = testCases.put(key, testCase);

        if (previous != null)
        {
            String message = "Test case with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    /**
     * Stores a private key on the temporary cache only if it is not already present. It can be used to hold a reference
     * to a private key in order to access it later, for example to sign a certificate. The id of the corresponding
     * certificate is used as the key for storing and retrieving the key.
     *
     * @param privateKey the private key.
     * @param id the id of the certificate corresponding to this privateKey.
     *
     * @throws DuplicateKeyException if a private key with the same id is already present.
     * @throws IllegalArgumentException if this id is null or empty or the private key is null.
     */
    public void addPrivateKey(String id, PrivateKey privateKey) throws DuplicateKeyException
    {

        if (id == null || id.isEmpty())
        {
            String message = "Id for this private key is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        if (privateKey == null)
        {
            String message = "Private key is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = id.trim();

        Object previous = privateKeys.put(key, privateKey);

        if (previous != null)
        {
            String message = "Private key with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    /**
     * Stores a public key on the temporary cache only if it is not already present. It can be used to hold a reference
     * to a public key in order to access it later, for example to calculate an authority key identifier. The id of the
     * corresponding certificate is used as the key for storing and retrieving the key.
     *
     * @param publicKey the encoded public key.
     * @param id the id of the certificate corresponding to this publicKey.
     *
     * @throws DuplicateKeyException if a public key with the same id is already present.
     * @throws IllegalArgumentException if this id is null or empty.
     */
    public void addPublicKey(String id, byte[] publicKey) throws DuplicateKeyException
    {

        if (id == null || id.isEmpty())
        {
            String message = "Id for this public key is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = id.trim();

        Object previous = publicKeys.put(key, publicKey);

        if (previous != null)
        {
            String message = "Public key with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }

    }

    /**
     * Stores an encoded certificate on the temporary cache only if it is not already present. It can be used to hold a
     * reference to a certificate in order to access it later, for example to store it on the filesystem. The id of the
     * corresponding certificate is used as the key for storing and retrieving the certificate.
     *
     * @param id the id of the certificate corresponding to this certificate.
     * @param certificate the encoded certificate.
     *
     * @throws DuplicateKeyException if a certificate with the same id is already present.
     * @throws IllegalArgumentException if this id is null or empty.
     */
    public void addCertificate(String id, byte[] certificate) throws DuplicateKeyException
    {

        if (id == null || id.isEmpty())
        {
            String message = "Id for this raw certificate is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = id.trim();

        Object previous = rawCertificates.put(key, certificate);

        if (previous != null)
        {
            String message = "Raw certificate with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    /**
     * Stores an encoded CRL on the temporary cache only if it is not already present. It can be used to hold a
     * reference to a CRL in order to access it later, for example to store it on the filesystem. The id of the
     * corresponding CRL is used as the key for storing and retrieving the CRL.
     *
     * @param id the id of the CRL corresponding to this crl.
     * @param crl the encoded CRL.
     *
     * @throws DuplicateKeyException if a CRL with the same id is already present.
     * @throws IllegalArgumentException if this id is null or empty.
     */
    public void addCRL(String id, byte[] crl) throws DuplicateKeyException
    {

        if (id == null || id.isEmpty())
        {
            String message = "Id for this raw CRL is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = id.trim();

        Object previous = rawCrls.put(key, crl);

        if (previous != null)
        {
            String message = "Raw CRL with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    public void addOCSPResponse(String id, byte[] ocspResponse) throws DuplicateKeyException
    {

        if (StringUtils.isEmpty(id))
        {
            String message = "Id for this raw OCSP Response is empty. Cannot store it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        String key = id.trim();

        Object previous = rawOcspResponses.put(key, ocspResponse);

        if (previous != null)
        {
            String message = "Raw OCSP with ID '" + key + "' already exists.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    /**
     * Retrieves the certificate identified by this id.
     *
     * @param id the id with which the certificate is stored in the cache.
     *
     * @return the certificate associated to this id or null if no certificate is associated to this id.
     */
    public Certificate getCertificate(String id)
    {
        return certificates.get(id);
    }

    public Certificate getResolvedCertificate(String id)
    {
        return resolvedCertificates.get(id);
    }

    /**
     * Retrieves the raw certificate identified by this id.
     *
     * @param id the id with which the raw certificate is stored in the cache.
     *
     * @return the raw certificate associated to this id or null if no raw certificate is associated to this id.
     */
    public byte[] getRawCertificate(String id)
    {
        return rawCertificates.get(id);
    }

    /**
     * Retrieves the CRL identified by this id.
     *
     * @param id the id with which the CRL is stored in the cache.
     *
     * @return the CRL associated to this id or null if no CRL is associated to this id.
     */
    public CRL getCRL(String id)
    {
        return crls.get(id);
    }

    /**
     * Retrieves the raw CRL identified by this id.
     *
     * @param id the id with which the raw CRL is stored in the cache.
     *
     * @return the raw CRL associated to this id or null if no raw CRL is associated to this id.
     */
    public byte[] getRawCRL(String id)
    {
        return rawCrls.get(id);
    }

    /**
     * Retrieves the OCSP response identified by this id.
     *
     * @param id the id with which the OCSP response is stored in the cache.
     *
     * @return the OCSP response associated to this id or null if no OCSP response is associated to this id.
     */
    public OcspResponse getOcspResponse(String id)
    {
        return ocspResponses.get(id);
    }

    /**
     * Retrieves the raw OCSP response identified by this id.
     *
     * @param id the id with which the raw OCSP response is stored in the cache.
     *
     * @return the raw OCSP response associated to this id or null if no raw OCSP response is associated to this id.
     */
    public byte[] getRawOcspResponse(String id)
    {
        return rawOcspResponses.get(id);
    }

    /**
     * Retrieves the private key identified by this id.
     *
     * @param id the id with which the private key is stored in the cache.
     *
     * @return the private key associated to this id or null if no private key is associated to this id.
     */
    public PrivateKey getPrivateKey(String id)
    {
        return privateKeys.get(id);
    }

    /**
     * Retrieves the encoded public key identified by this id.
     *
     * @param id the id with which the public key is stored in the cache.
     *
     * @return the public key associated to this id or null if no public key is associated to this id.
     */
    public byte[] getPublicKey(String id)
    {
        return publicKeys.get(id);
    }

    /**
     * Retrieves the test case identified by this id.
     *
     * @param id the id with which the test case is stored in the cache.
     *
     * @return the test case associated to this id or null if no test case is associated to this id.
     */
    public TestCase getTestCase(String id)
    {
        return testCases.get(id);
    }

    public ConcurrentHashMap<String, TestCase> getTestCases()
    {
        return testCases;
    }

    public void addPKIobjectsToTestCase(String testCaseId, PKIObjects pkiObjects)
    {

        if (testCaseId == null || testCaseId.isEmpty())
        {
            String message = "The id of the test case is empty or null. Cannot assign PKI objects to it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        Object previous = testCasePKIObjects.put(testCaseId, pkiObjects);

        if (previous != null)
        {
            Utils.logError("PKI Objects have already been assiged to test case with id '" + testCaseId + "'");
        }

    }

    public PKIObjects getPKIobjectsFromTestCase(String testCaseId)
    {

        if (testCaseId == null || testCaseId.isEmpty())
        {
            String message = "The id of the test case is empty or null. Cannot assign PKI objects to it.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        return testCasePKIObjects.get(testCaseId);
    }

    public void assignCertificateIdToTestCase(TestCase testCase, Certificate certificate)
    {

        String testCaseId = Utils.getTestCaseId(testCase);
        String certificateId = Utils.getCertificateId(certificate);

        List<String> certificateIdList = (List<String>) testCaseToCertificateMap.get(testCaseId);

        if (certificateIdList == null)
        {
            certificateIdList = new ArrayList<>();
            certificateIdList.add(certificateId);
        }
        else
        {
            certificateIdList.add(certificateId);
        }
        testCaseToCertificateMap.put(testCaseId, certificateIdList);
    }

    public void assignTestCaseToCertificateId(Certificate certificate, TestCase testCase)
    {
        String testCaseId = Utils.getTestCaseId(testCase);
        String certificateId = Utils.getCertificateId(certificate);
        certificateToTestCaseMap.put(certificateId, testCaseId);
    }

    public String getTestCaseId(String certificateId)
    {
        return certificateToTestCaseMap.get(certificateId);
    }

    public void assignCRLIdToTestCase(TestCase testCase, CRL crl)
    {
        String crlId = Utils.getCRLId(crl);

        String testCaseId = Utils.getTestCaseId(testCase);

        List<String> crlIdList = testCaseToCRLMap.get(testCaseId);

        if (crlIdList == null)
        {
            crlIdList = new ArrayList<>();
            crlIdList.add(crlId);
        }
        else
        {
            crlIdList.add(crlId);
        }
        testCaseToCRLMap.put(testCaseId, crlIdList);
    }


    public void assignOCSPIdToTestCase(TestCase testCase, OcspResponse ocspResponse)
    {
        Optional<String> ocspId = Utils.getOcspResponseId(ocspResponse);

        String testCaseId = Utils.getTestCaseId(testCase);

        List<String> ocspIdList = testCaseToOCSPMap.get(testCaseId);

        if (ocspIdList == null)
        {
            ocspIdList = new ArrayList<>();
            ocspIdList.add(ocspId.get());
        }
        else
        {
            ocspIdList.add(ocspId.get());
        }
        testCaseToOCSPMap.put(testCaseId, ocspIdList);
    }

    public void assignTestCaseToOCSPId(OcspResponse ocspResponse, TestCase testCase)
    {
        String testCaseId = Utils.getTestCaseId(testCase);
        Optional<String> ocspResponseId = Utils.getOcspResponseId(ocspResponse);
        ocspResponseToTestCaseMap.put(ocspResponseId.get(), testCaseId);
    }

    public void assignTestCaseToCRLId(CRL crl, TestCase testCase)
    {
        String testCaseId = Utils.getTestCaseId(testCase);
        String crlId = Utils.getCRLId(crl);
        crlToTestCaseMap.put(crlId, testCaseId);
    }

    public void assignIssuerToCertificate(String certificateId, String issuerId)
    {
        String returnValue = certificateIssuerMap.put(certificateId, issuerId);

        if (returnValue != null)
        {
            String error = "Certificate with id '" + certificateId + "' has already been assigned to an issuer.";
            Utils.exitProgramm(error);
        }
    }

    public String getIssuerId(String certificateId)
    {
        String issuerId = certificateIssuerMap.get(certificateId);
        return issuerId;
    }

    public List<String> getCertificateIds(String testCaseId)
    {
        List<String> certificateIdList = testCaseToCertificateMap.get(testCaseId);

        if (certificateIdList == null)
        {
            certificateIdList = new ArrayList<>();
        }

        return certificateIdList;
    }

    public List<String> getCRLIds(String testCaseName)
    {
        List<String> crlIdList = testCaseToCRLMap.get(testCaseName);

        if (crlIdList == null)
        {
            crlIdList = new ArrayList<>();
        }

        return crlIdList;

    }


    public List<String> getOCSPResponsesIds(String testCaseName)
    {
        List<String> ocspResponseIdList = testCaseToOCSPMap.get(testCaseName);

        if (ocspResponseIdList == null)
        {
            ocspResponseIdList = new ArrayList<>();
        }

        return ocspResponseIdList;

    }

    public ConcurrentHashMap<String, String> getHTTPCRLDPs()
    {
        return httpCRLDPs;
    }

    public ConcurrentHashMap<String, String> getLDAPCRLDPs()
    {
        return ldapCRLDPs;
    }

    public ConcurrentHashMap<String, String> getOcspAIAs()
    {
        return ocspAIAs;
    }

    public void addHTTPCRLDP(String crldp, String crlId) throws DuplicateKeyException
    {
        Object previous = httpCRLDPs.put(crldp, crlId);
        if (previous != null)
        {
            String message = "CRLDP '" + crldp + "' has already been specified for CRL '" + previous + "'.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    public void addLDAPCRLDP(String crldp, String crlId) throws DuplicateKeyException
    {
        Object previous = ldapCRLDPs.put(crldp, crlId);
        if (previous != null)
        {
            String message = "CRLDP '" + crldp + "' has already been specified for CRL '" + previous + "'.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }


    public void addOcspAia(String ocspAia, String ocspResponseID) throws DuplicateKeyException
    {
        Object previous = ocspAIAs.put(ocspAia, ocspResponseID);
        if (previous != null)
        {
            String message = "OCSP AIA '" + ocspAia + "' has already been specified for OCSP response '" + previous + "'.";
            Utils.logError(message);
            throw new DuplicateKeyException(message);
        }
    }

    /**
     * Returns the object cache that holds PKI objects during their creation.
     *
     * @return the singleton instance of this cache.
     */
    public static ObjectCache getInstance()
    {
        if (objectCache == null)
        {
            synchronized (ObjectCache.class)
            {
                if (objectCache == null)
                {
                    objectCache = new ObjectCache();
                }
            }
        }
        return objectCache;
    }

    /**
     * Removes all objects from this cache.
     */
    public void clear()
    {
        certificates.clear();
        testCases.clear();
        crls.clear();
        privateKeys.clear();
        publicKeys.clear();
        rawCertificates.clear();
        rawCrls.clear();
        testCasePKIObjects.clear();
        testCaseToCertificateMap.clear();
        testCaseToCRLMap.clear();
        certificateToTestCaseMap.clear();
        crlToTestCaseMap.clear();
        certificateIssuerMap.clear();
        httpCRLDPs.clear();
        ldapCRLDPs.clear();
        ocspAIAs.clear();
        resolvedCertificates.clear();
        ocspResponses.clear();
        rawOcspResponses.clear();
        ocspResponseToTestCaseMap.clear();
        testCaseToOCSPMap.clear();
        serialNumbers.clear();
        errors.clear();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {

        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Number of certificates (XML):\t" + certificates.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of CRLs (XML):\t\t" + crls.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of test cases:\t\t" + testCases.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of raw certificates:\t" + rawCertificates.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of raw CRLs:\t\t" + rawCrls.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of private keys:\t\t" + privateKeys.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of public keys:\t\t" + publicKeys.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of mapped certificates:\t" + certificateToTestCaseMap.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of mapped crls:\t\t" + crlToTestCaseMap.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of mapped cert. iss.:\t" + certificateIssuerMap.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of OCSP AIAs:\t" + ocspAIAs.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of resolved certificates:\t" + resolvedCertificates.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of OCSP responses:\t" + ocspResponses.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of raw OCSP responses:\t" + rawOcspResponses.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of mapped OCSP responses:\t" + ocspResponseToTestCaseMap.size());
        stringBuilder.append(System.getProperty("line.separator"));
        stringBuilder.append("Number of serail numbers:\t" + serialNumbers.size());
        stringBuilder.append(System.getProperty("line.separator"));

        mapToString(stringBuilder, certificates, "Certificate Ids: \t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, crls, "CRL Ids: \t\t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, testCases, "Test case Ids: \t\t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, privateKeys, "Private key Ids: \t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, publicKeys, "Public key Ids: \t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, rawCertificates, "Raw certificate Ids: \t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, rawCrls, "Raw CRL Ids: \t\t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, certificateToTestCaseMap, "Mapped certificate Ids: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, crlToTestCaseMap, "Mapped CRL Ids: \t[");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, certificateIssuerMap, "Mapped cert. iss. Ids: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, ocspAIAs, "OCSP AIAs: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, resolvedCertificates, "Resolved certificates: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, ocspResponses, "OCSP Responses: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, rawOcspResponses, "Raw OCSP Responses: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, ocspResponseToTestCaseMap, "Mapped OCSP Ids: [");
        stringBuilder.append(System.getProperty("line.separator"));
        mapToString(stringBuilder, serialNumbers, "Serial Numbers: [");
        stringBuilder.append(System.getProperty("line.separator"));



        return stringBuilder.toString();
    }

    private StringBuilder mapToString(StringBuilder stringBuilder, ConcurrentHashMap<?, ?> map, String title)
    {

        stringBuilder.append(title);

        if (!map.isEmpty())
        {
            for (Object key : map.keySet())
            {
                stringBuilder.append((String) key);
                stringBuilder.append(", ");
            }
            stringBuilder.delete(stringBuilder.length() - 2, stringBuilder.length());
            stringBuilder.append("]");
        }
        else
        {
            stringBuilder.append("]");
        }

        return stringBuilder;
    }

}
