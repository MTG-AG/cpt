
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import de.mtg.certpathtest.pkiobjects.CertStatus;
import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.NextUpdate;
import de.mtg.certpathtest.pkiobjects.OcspResponse;
import de.mtg.certpathtest.pkiobjects.ProducedAt;
import de.mtg.certpathtest.pkiobjects.ResponderId;
import de.mtg.certpathtest.pkiobjects.ResponseEntry;
import de.mtg.certpathtest.pkiobjects.RevocationDate;
import de.mtg.certpathtest.pkiobjects.ThisUpdate;
import de.mtg.certpathtest.pkiobjects.extensions.AuthorityInformationAccess;
import de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints;
import de.mtg.certpathtest.pkiobjects.extensions.CRLDP;
import de.mtg.certpathtest.pkiobjects.extensions.CRLNumber;
import de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer;
import de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies;
import de.mtg.certpathtest.pkiobjects.extensions.DeltaCRLIndicator;
import de.mtg.certpathtest.pkiobjects.extensions.ExtendedKeyUsage;
import de.mtg.certpathtest.pkiobjects.extensions.InhibitAnyPolicy;
import de.mtg.certpathtest.pkiobjects.extensions.InvalidityDate;
import de.mtg.certpathtest.pkiobjects.extensions.IssuingDistributionPoint;
import de.mtg.certpathtest.pkiobjects.extensions.KeyUsage;
import de.mtg.certpathtest.pkiobjects.extensions.NameConstraints;
import de.mtg.certpathtest.pkiobjects.extensions.PolicyConstraints;
import de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings;
import de.mtg.certpathtest.pkiobjects.extensions.ReasonCode;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectDirectoryAttributes;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectInformationAccess;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectOrIssuerAlternativeName;
import de.mtg.certpathtest.pkiobjects.extensions.UnknownExtension;
import de.mtg.certpathtest.pkiobjects.extensions.XMLExtension;
import de.mtg.certpathtest.validators.ConcreteValuesSetValidator;
import de.mtg.certpathtest.validators.DNValidator;
import de.mtg.certpathtest.validators.DateValidator;
import de.mtg.certpathtest.validators.IntegerValidator;
import de.mtg.certpathtest.validators.ModificationValidator;
import de.mtg.certpathtest.validators.PrivateKeyValidator;
import de.mtg.certpathtest.validators.RegExpValidator;
import de.mtg.security.asn1.x509.ocsp.SimpleBasicOCSPResponse;
import de.mtg.security.asn1.x509.ocsp.SimpleCertID;
import de.mtg.security.asn1.x509.ocsp.SimpleOCSPResponse;
import de.mtg.security.asn1.x509.ocsp.SimpleResponseBytes;
import de.mtg.security.asn1.x509.ocsp.SimpleResponseData;
import de.mtg.security.asn1.x509.ocsp.SimpleSingleResponse;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class TestToolOCSPResponse
{
    private static Logger logger = LoggerFactory.getLogger(TestToolOCSPResponse.class);

    private byte[] encodedValue = null;

    private static ObjectCache objectCache = ObjectCache.getInstance();

    /**
     * Constructs a newly allocated TestToolOCSPResponse object.
     *
     * <ul>
     * <li>It extracts the data from this xmlOcspResponse.</li>
     * <li>It verifies that these data are correct.</li>
     * </ul>
     */
    public TestToolOCSPResponse() throws Exception
    {

    }

    /**
     * Constructs a newly allocated TestToolOCSPResponse object.
     *
     * <ul>
     * <li>It extracts the data from this xmlOcspResponse.</li>
     * <li>It verifies that these data are correct.</li>
     * </ul>
     */
    public void createOCSPResponse(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse) throws Exception
    {

        String ocspResponseId = ocspResponse.getId();
        int responseStatus = getResponseStatus(ocspResponse);

        if (responseStatus != 0)
        {
            SimpleOCSPResponse simpleOCSPResponse = new SimpleOCSPResponse();
            simpleOCSPResponse.setResponseStatus(new ASN1Enumerated(responseStatus));
            encodedValue = simpleOCSPResponse.getEncoded(ASN1Encoding.DER);
            return;
        }

        BigInteger version = getVersion(ocspResponse);
        AlgorithmIdentifier signatureOID = getAlgorithmIdentifier(ocspResponse);

        de.mtg.certpathtest.pkiobjects.Modification modification = ocspResponse.getModification();

        if (modification != null)
        {
            TestToolCertificate.checkInputData(modification, new ModificationValidator(),
                                               "Wrong value for modification in XML OCSP with id '" + ocspResponseId + "'.");
        }

        de.mtg.certpathtest.Modification modificationValue =
                Optional.ofNullable(modification).map(mod -> de.mtg.certpathtest.Modification.valueOf(mod.getId()))
                        .orElse(null);

        ResponseEntry responseEntry = ocspResponse.getResponseEntry();

        SimpleCertID simpleCertID = new SimpleCertID();
        simpleCertID.setHashAlgorithm(getHashAlgorithmIdentifier(responseEntry, ocspResponseId));
        simpleCertID.setIssuerKeyHash(getIssuerKeyHash(responseEntry));
        simpleCertID.setIssuerNameHash(getIssuerNameHash(responseEntry));
        simpleCertID.setSerialNumber(getResponseEntrySerialNumber(responseEntry));

        SimpleSingleResponse simpleSingleResponse = new SimpleSingleResponse();
        simpleSingleResponse.setCertID((ASN1Sequence) simpleCertID.toASN1Primitive());
        simpleSingleResponse.setNextUpdate(getNextUpdate(responseEntry, ocspResponseId));
        simpleSingleResponse.setThisUpdate(getThisUpdate(responseEntry, ocspResponseId));
        simpleSingleResponse.setCertStatus(getCertStatus(responseEntry, ocspResponseId));
        List<Extension> singleResponseExtensions = ocspResponse.getResponseEntry().getExtensions();

        if (CollectionUtils.isNotEmpty(singleResponseExtensions))
        {
            ASN1Sequence singleExtensions = getExtensions(singleResponseExtensions);
            DERTaggedObject taggedExtensions = new DERTaggedObject(true, 1, singleExtensions);
            simpleSingleResponse.setSingleExtensions(taggedExtensions);
        }

        SimpleResponseData simpleResponseData = new SimpleResponseData();
        ASN1TaggedObject taggedVersion = new DERTaggedObject(true, 0, new ASN1Integer(version));
        simpleResponseData.setVersion(taggedVersion);
        ASN1TaggedObject responderId = getResponderId(ocspResponse);
        if (responderId != null)
        {
            simpleResponseData.setResponderID(getResponderId(ocspResponse));
        }
        simpleResponseData.setProducedAt(getProducedAt(ocspResponse));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(simpleSingleResponse);
        DERSequence responses = new DERSequence(vector);
        simpleResponseData.setResponses(responses);

        List<Extension> extensions = ocspResponse.getExtensions();

        if (CollectionUtils.isNotEmpty(extensions))
        {
            ASN1Sequence responseExtensions = getExtensions(extensions);
            DERTaggedObject taggedExtensions = new DERTaggedObject(true, 1, responseExtensions);
            simpleResponseData.setResponseExtensions(taggedExtensions);
        }

        // BasicOCSPResponse       ::= SEQUENCE {
        // tbsResponseData      ResponseData,
        // signatureAlgorithm   AlgorithmIdentifier,
        // signature            BIT STRING,
        // certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

        SimpleBasicOCSPResponse simpleBasicOCSPResponse = new SimpleBasicOCSPResponse();
        ASN1Sequence tbsResponseData = (ASN1Sequence) simpleResponseData.toASN1Primitive();
        simpleBasicOCSPResponse.setTbsResponseData(tbsResponseData);
        simpleBasicOCSPResponse.setSignatureAlgorithm(signatureOID);

        byte[] rawSignature = getRawSignature(ocspResponse, tbsResponseData.getEncoded(ASN1Encoding.DER), signatureOID,
                                              modificationValue);
        simpleBasicOCSPResponse.setSignature(new DERBitString(rawSignature));

        // add OCSP signer cert
        if (StringUtils.isNotEmpty(ocspResponse.getOcspCertId()))
        {
            String ocspCertId = ocspResponse.getOcspCertId();
            byte[] rawOcspCert = objectCache.getRawCertificate(ocspCertId);

            if (rawOcspCert == null) {
                Utils.logError("OCSP certificate to be added in the response was not found.");
            }

            ASN1Sequence issuerCertSeq;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(rawOcspCert))
            {
                issuerCertSeq = (ASN1Sequence) asn1InputStream.readObject();
            }
            ASN1EncodableVector certsVector = new ASN1EncodableVector();
            certsVector.add(issuerCertSeq);
            DERSequence certSeq = new DERSequence(certsVector);
            DERTaggedObject taggedCertSeq = new DERTaggedObject(true, 0, certSeq);
            simpleBasicOCSPResponse.setCerts(taggedCertSeq);
        }
        // END add OCSP signer cert

        SimpleResponseBytes simpleResponseBytes = new SimpleResponseBytes();
        simpleResponseBytes.setResponseType(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"));
        ASN1OctetString responseBytes = new DEROctetString(
                ((ASN1Sequence) simpleBasicOCSPResponse.toASN1Primitive()).getEncoded(ASN1Encoding.DER));
        simpleResponseBytes.setResponse(responseBytes);

        SimpleOCSPResponse simpleOCSPResponse = new SimpleOCSPResponse();
        simpleOCSPResponse.setResponseStatus(new ASN1Enumerated(responseStatus));
        DERTaggedObject tagged = new DERTaggedObject(true, 0, simpleResponseBytes);
        simpleOCSPResponse.setResponseBytes(tagged);

        encodedValue = simpleOCSPResponse.getEncoded(ASN1Encoding.DER);
    }


    public static ASN1Sequence getExtensions(List<Extension> extensions) throws Exception
    {
        ASN1EncodableVector extVector = new ASN1EncodableVector();

        for (Extension extension : extensions)
        {

            String oid = extension.getOid();

            if (oid == null || oid.isEmpty())
            {
                String message = "Missing OID in OCSP response extension.";
                Utils.logError(message);
                throw new IllegalArgumentException(message);
            }

            XMLExtension xmlExtension = null;

            if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId()))
            {
                String type = extension.getType().trim();

                if (!"raw".equalsIgnoreCase(type))
                {
                    Utils.exitProgramm(
                            "Only the type raw is allowed for the Authority Key Identifier when used in OCSP " +
                                    "responces. Will not add this extension.");
                }
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()))
            {
                String type = extension.getType().trim();

                if (!"raw".equalsIgnoreCase(type))
                {
                    Utils.exitProgramm(
                            "Only the type raw is allowed for the Subject Key Identifier when used in OCSP responces." +
                                    " Will not add this extension.");
                }
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.keyUsage.getId()))
            {
                xmlExtension = new KeyUsage(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId()))
            {
                xmlExtension = new CertificatePolicies(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId()))
            {
                xmlExtension = new BasicConstraints(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.policyMappings.getId()))
            {
                xmlExtension = new PolicyMappings(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName.getId()))
            {
                xmlExtension = new SubjectOrIssuerAlternativeName(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName.getId()))
            {
                xmlExtension = new SubjectOrIssuerAlternativeName(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId()))
            {
                xmlExtension = new SubjectDirectoryAttributes(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.nameConstraints.getId()))
            {
                xmlExtension = new NameConstraints(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.policyConstraints.getId()))
            {
                xmlExtension = new PolicyConstraints(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage.getId()))
            {
                xmlExtension = new ExtendedKeyUsage(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId()))
            {
                xmlExtension = new CRLDP(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy.getId()))
            {
                xmlExtension = new InhibitAnyPolicy(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.freshestCRL.getId()))
            {
                xmlExtension = new CRLDP(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId()))
            {
                xmlExtension = new AuthorityInformationAccess(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess.getId()))
            {
                xmlExtension = new SubjectInformationAccess(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.cRLNumber.getId()))
            {
                xmlExtension = new CRLNumber(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator.getId()))
            {
                xmlExtension = new DeltaCRLIndicator(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint.getId()))
            {
                xmlExtension = new IssuingDistributionPoint(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.reasonCode.getId()))
            {
                xmlExtension = new ReasonCode(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.invalidityDate.getId()))
            {
                xmlExtension = new InvalidityDate(extension);
            }
            else if (oid.equals(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId()))
            {
                xmlExtension = new CertificateIssuer(extension);
            }
            else
            {
                xmlExtension = new UnknownExtension(extension);
            }

            if (xmlExtension != null)
            {
                extVector.add(xmlExtension.getSimpleExtensionAsSequence());
            }
        }

        return new DERSequence(extVector);
    }


    public byte[] getEncoded()
    {
        return encodedValue;
    }

    private static BigInteger getVersion(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse)
    {
        String version = ocspResponse.getVersion();
        TestToolCertificate.checkInputData(version, new IntegerValidator(), "Wrong value '" + version
                + "' for version in XML OCSP with id '" + ocspResponse.getId() + "'.");
        return new BigInteger(version);
    }


    private static ASN1Integer getResponseEntrySerialNumber(
            de.mtg.certpathtest.pkiobjects.ResponseEntry responseEntry) throws
            CertificateException, IOException
    {
        String refid = responseEntry.getRefid();
        Certificate certificate = objectCache.getCertificate(refid);
        byte[] rawCert = objectCache.getRawCertificate(Utils.getCertificateId(certificate));

        InputStream is = new ByteArrayInputStream(rawCert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        is.close();

        return new ASN1Integer(cert.getSerialNumber());
    }

    private Time getProducedAt(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse)
    {
        ProducedAt producedAt = ocspResponse.getProducedAt();
        TestToolCertificate.checkInputData(producedAt, new DateValidator(),
                                           "Wrong value for producedAt in XML OCSP with id '" + ocspResponse.getId()
                                                   + "'.");
        String value = producedAt.getValue();
        Time time = Utils.convertValue(value, producedAt.getEncoding());
        return time;
    }

    private Time getThisUpdate(de.mtg.certpathtest.pkiobjects.ResponseEntry responseEntry, String ocspResponseId)
    {
        ThisUpdate thisUpdate = responseEntry.getThisUpdate();
        TestToolCertificate.checkInputData(thisUpdate, new DateValidator(),
                                           "Wrong value for thisUpdate in XML OCSP with id '" + ocspResponseId + "'.");
        String value = thisUpdate.getValue();
        Time time = Utils.convertValue(value, thisUpdate.getEncoding());
        return time;
    }

    private ASN1TaggedObject getNextUpdate(de.mtg.certpathtest.pkiobjects.ResponseEntry responseEntry,
                                           String ocspResponseId)
    {

        NextUpdate nextUpdate = responseEntry.getNextUpdate();

        if (nextUpdate == null)
        {
            return null;
        }
        TestToolCertificate.checkInputData(nextUpdate, new DateValidator(),
                                           "Wrong value for nextUpdate in XML OCSP with id '" + ocspResponseId + "'.");
        String value = nextUpdate.getValue();
        Time time = Utils.convertValue(value, nextUpdate.getEncoding());
        ASN1TaggedObject tagged = new DERTaggedObject(true, 0, time);
        return tagged;
    }

    private PrivateKey getSignatureKey(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse)
    {
        String verifiedBy = ocspResponse.getVerifiedBy();
        verifiedBy = verifiedBy.trim();
        TestToolCertificate.checkInputData(verifiedBy, new PrivateKeyValidator(),
                                           "Wrong value for VerifiedBy in XML OCSP response with id '" + ocspResponse.getId() +
                                                   "'.");
        return objectCache.getPrivateKey(verifiedBy);
    }

    private int getResponseStatus(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse)
    {

        String responseStatus = ocspResponse.getResponseStatus();

        if (StringUtils.isEmpty(responseStatus))
        {
            String message = "Empty response status in XML OCSP with id '" + ocspResponse.getId() + "'.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        RegExpValidator regexpValidator = new RegExpValidator("-?\\d+");
        boolean isNumber = regexpValidator.validate(responseStatus.trim());
        if (isNumber)
        {
            return Integer.parseInt(responseStatus);
        }

        ConcreteValuesSetValidator concreteValuesValidator = new ConcreteValuesSetValidator(
                "successful",
                "malformedRequest",
                "internalError",
                "tryLater",
                "sigRequired",
                "unauthorized");

        TestToolCertificate.checkInputData(responseStatus, concreteValuesValidator,
                                           "Wrong value '" + responseStatus + "' for responseStatus in XML OCSP with " +
                                                   "id '" + ocspResponse.getId
                                                   () + "'.");

        if (StringUtils.equalsIgnoreCase("successful", responseStatus.trim()))
        {
            return 0;
        }

        if (StringUtils.equalsIgnoreCase("malformedRequest", responseStatus.trim()))
        {
            return 1;
        }

        if (StringUtils.equalsIgnoreCase("internalError", responseStatus.trim()))
        {
            return 2;
        }

        if (StringUtils.equalsIgnoreCase("tryLater", responseStatus.trim()))
        {
            return 3;
        }

        if (StringUtils.equalsIgnoreCase("sigRequired", responseStatus.trim()))
        {
            return 5;
        }

        if (StringUtils.equalsIgnoreCase("unauthorized", responseStatus.trim()))
        {
            return 6;
        }

        return 0;

    }

    private AlgorithmIdentifier getAlgorithmIdentifier(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse)
    {

        String signatureOID = ocspResponse.getSignature();
        TestToolCertificate.checkInputData(signatureOID, new RegExpValidator("(\\d+\\.{1})*\\d+"),
                                           "Wrong value for signatureOID in XML OCSP with id '" + ocspResponse.getId
                                                   () + "'.");

        if (isAlgorithmRSA(signatureOID))
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID), DERNull.INSTANCE);
        }
        else
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID));
        }
    }

    private AlgorithmIdentifier getHashAlgorithmIdentifier(de.mtg.certpathtest.pkiobjects.ResponseEntry responseEntry,
                                                           String ocspResponseId)
    {

        String hashOID = responseEntry.getHashAlgorithm();
        TestToolCertificate.checkInputData(hashOID, new RegExpValidator("(\\d+\\.{1})*\\d+"),
                                           "Wrong value for hashOID in XML OCSP with id '" + ocspResponseId + "'.");
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashOID));
    }


    private byte[] getRawSignature(de.mtg.certpathtest.pkiobjects.OcspResponse ocspResponse, byte[] rawBytes,
                                   AlgorithmIdentifier algorithmIdentifier,
                                   de.mtg.certpathtest.Modification modification)
            throws SignatureException, IOException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException
    {

        PrivateKey privateKey = getSignatureKey(ocspResponse);

        if (modification != null)
        {
            if (de.mtg.certpathtest.Modification.EMPTY_SIGNATURE.equals(modification))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.EMPTY_SIGNATURE);
                return null;
            }
            else if (de.mtg.certpathtest.Modification.WRONG_SIGNATURE.equals(modification))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.WRONG_SIGNATURE);
                Random random = new Random();
                random.nextBytes(rawBytes);
            }
            else if (de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.equals(modification))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION);
            }
        }

        Signature signature = Signature.getInstance(algorithmIdentifier.getAlgorithm().toString(), "BC");
        signature.initSign(privateKey);
        signature.update(rawBytes);
        byte[] rawSignature = signature.sign();
        return rawSignature;

    }

    private boolean isAlgorithmRSA(String signatureOID)
    {
        if (signatureOID.startsWith("1.2.840.113549.1.1"))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    private static DEROctetString getIssuerKeyHash(
            de.mtg.certpathtest.pkiobjects.ResponseEntry responseEntry) throws CertificateException, IOException,
            NoSuchAlgorithmException, NoSuchProviderException
    {
        String hashOID = responseEntry.getHashAlgorithm();
        hashOID = hashOID.trim();
        X509Certificate issuerCert = getIssuerCertificate(responseEntry);
        return getKeyHash(issuerCert.getPublicKey(), hashOID);
    }

    private static DEROctetString getKeyHash(PublicKey publicKey, String hashOID) throws NoSuchAlgorithmException,
            NoSuchProviderException
    {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return getKeyHash(spki, hashOID);
    }

    private static DEROctetString getKeyHash(SubjectPublicKeyInfo spki, String hashOID) throws NoSuchAlgorithmException,
            NoSuchProviderException
    {
        byte[] tbdDigested = spki.getPublicKeyData().getBytes();
        MessageDigest md = MessageDigest.getInstance(hashOID, "BC");
        md.reset();
        byte[] result = md.digest(tbdDigested);
        return new DEROctetString(result);
    }

    private static DEROctetString getIssuerNameHash(
            ResponseEntry responseEntry) throws CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException
    {
        String hashOID = responseEntry.getHashAlgorithm();
        hashOID = hashOID.trim();
        X509Certificate issuerCert = getIssuerCertificate(responseEntry);
        return getSubjectNameHash(issuerCert, hashOID);
    }


    private static DEROctetString getSubjectNameHash(
            X509Certificate certificate, String hashOID) throws NoSuchProviderException, NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(hashOID, "BC");
        md.update(certificate.getSubjectX500Principal().getEncoded());
        byte[] result = md.digest();
        return new DEROctetString(result);
    }

    private static X509Certificate getIssuerCertificate(
            ResponseEntry responseEntry) throws CertificateException, IOException
    {
        String refid = responseEntry.getRefid();
        Certificate certificate = objectCache.getResolvedCertificate(refid);
        String issuerId = certificate.getVerifiedBy();

        byte[] rawIssuerCert = objectCache.getRawCertificate(issuerId);

        InputStream is = new ByteArrayInputStream(rawIssuerCert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate issuerCert = (X509Certificate) cf.generateCertificate(is);
        is.close();
        return issuerCert;
    }


    private static ASN1TaggedObject getCertStatus(ResponseEntry responseEntry,
                                                  String ocspResponseId)
    {
        CertStatus status = responseEntry.getCertStatus();

        String infoStatus = status.getStatus();
        ConcreteValuesSetValidator concreteValuesValidator = new ConcreteValuesSetValidator(
                "good",
                "revoked",
                "unknown");
        TestToolCertificate.checkInputData(infoStatus, concreteValuesValidator, "Wrong value '" + infoStatus
                + "' for cert status in XML OCSP with id '" + ocspResponseId + "'.");

        int tagNumber = -1;
        ASN1TaggedObject certStatus = null;
        if (StringUtils.equalsIgnoreCase("good", infoStatus))
        {
            tagNumber = 0;
            certStatus = new DERTaggedObject(false, tagNumber, DERNull.INSTANCE);
        }
        else if (StringUtils.equalsIgnoreCase("revoked", infoStatus))
        {
            RevocationDate revocationDate = status.getRevocationDate();
            TestToolCertificate.checkInputData(revocationDate, new DateValidator(),
                                               "Wrong value for revocationDate in XML OCSP.");
            String value = revocationDate.getValue();
            Time time = Utils.convertValue(value, revocationDate.getEncoding());
            tagNumber = 1;
            certStatus = new DERTaggedObject(false, tagNumber, time);
        }
        else
        {
            tagNumber = 2;
            certStatus = new DERTaggedObject(false, tagNumber, DERNull.INSTANCE);
        }

        return certStatus;
    }

    private static ASN1TaggedObject getResponderId(
            OcspResponse ocspResponse) throws CertificateException, IOException, NoSuchAlgorithmException,
            NoSuchProviderException
    {

        ResponderId responderId = ocspResponse.getResponderId();

        if (responderId == null)
        {
            return null;
        }
        String type = responderId.getType();
        String value = responderId.getValue();
        String encoding = responderId.getEncoding();
        ConcreteValuesSetValidator concreteValuesValidator = new ConcreteValuesSetValidator(
                "byName",
                "byKey");
        TestToolCertificate.checkInputData(type, concreteValuesValidator, "Wrong value '" + responderId.getType()
                + "' for type in responder ID in XML OCSP with id '" + ocspResponse.getId() + "'.");

        String verifiedBy = ocspResponse.getVerifiedBy();

        byte[] rawCert = objectCache.getRawCertificate(verifiedBy);
        InputStream is = new ByteArrayInputStream(rawCert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        is.close();

        ASN1TaggedObject responderID = null;

        if (StringUtils.equalsIgnoreCase("byName", type))
        {
            if (StringUtils.isEmpty(value))
            {
                ASN1Sequence seq;
                try (ASN1InputStream asn1InputStream = new ASN1InputStream(cert.getSubjectX500Principal().getEncoded()))
                {
                    seq = (ASN1Sequence) asn1InputStream.readObject();
                }
                responderID = new DERTaggedObject(true, 1, seq);
            }
            else
            {

                TestToolCertificate.checkInputData(responderId, new DNValidator(),
                                                   "Wrong value for issuer in XML OCSP response with id '" + ocspResponse.getId() + "'.");

                concreteValuesValidator = new ConcreteValuesSetValidator(
                        "UTF8",
                        "PrintableString");
                TestToolCertificate.checkInputData(encoding, concreteValuesValidator,
                                                   "Wrong value '" + responderId.getEncoding()
                                                           + "' for encoding in responder ID in XML OCSP with id '" + ocspResponse.getId() + "'.");

                if ("UTF8".equalsIgnoreCase(encoding.trim()))
                {
                    responderID = new DERTaggedObject(true, 1, new X500Name(value));
                }
                else if ("PrintableString".equalsIgnoreCase(encoding.trim()))
                {
                    responderID = new DERTaggedObject(true, 1, Utils.getAsPrintableStringName(value));
                }
            }
        }
        else
        {
            if (StringUtils.isEmpty(value))
            {
                DEROctetString octetStringValue = getKeyHash(cert.getPublicKey(), "SHA1");
                responderID = new DERTaggedObject(true, 2, octetStringValue);
            }
            else
            {
                byte[] rawKey = Base64.decode(value);
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rawKey);
                DEROctetString octetStringValue = getKeyHash(subjectPublicKeyInfo, "SHA1");
                responderID = new DERTaggedObject(true, 2, octetStringValue);
            }
        }

        return responderID;
    }


}
