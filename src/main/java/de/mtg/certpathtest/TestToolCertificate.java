
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.StringTokenizer;

import javax.xml.bind.JAXBException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.Modification;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import de.mtg.certpathtest.pkiobjects.SubjectDN;
import de.mtg.certpathtest.pkiobjects.extensions.AuthorityInformationAccess;
import de.mtg.certpathtest.pkiobjects.extensions.AuthorityKeyIdentifier;
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
import de.mtg.certpathtest.pkiobjects.extensions.SubjectKeyIdentifier;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectOrIssuerAlternativeName;
import de.mtg.certpathtest.pkiobjects.extensions.UnknownExtension;
import de.mtg.certpathtest.pkiobjects.extensions.XMLExtension;
import de.mtg.certpathtest.validators.BinaryStringValidator;
import de.mtg.certpathtest.validators.DNValidator;
import de.mtg.certpathtest.validators.DateValidator;
import de.mtg.certpathtest.validators.IntegerValidator;
import de.mtg.certpathtest.validators.ModificationValidator;
import de.mtg.certpathtest.validators.PrivateKeyValidator;
import de.mtg.certpathtest.validators.PublicKeyValidator;
import de.mtg.certpathtest.validators.RegExpValidator;
import de.mtg.security.asn1.x509.cert.SimpleCertificate;
import de.mtg.security.asn1.x509.cert.SimpleTBSCertificate;
import de.mtg.security.asn1.x509.common.SimpleExtension;

public class TestToolCertificate
{
    private static Logger logger = LoggerFactory.getLogger(TestToolCertificate.class);

    private byte[] encodedValue = null;

    /**
     *
     * Constructs a newly allocated TestToolCertificate object.
     *
     * <ul>
     * <li>It extracts the data from this xmlCertificate.</li>
     * <li>It verifies that these data are correct</li>
     * </ul>
     *
     *
     * @param xmlCertificate
     * @throws Exception
     */
    public TestToolCertificate(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate) throws Exception
    {

        String certificateId = xmlCertificate.getId();

        BigInteger version = getVersion(xmlCertificate);
        BigInteger serialNumber = getSerialNumber(xmlCertificate);
        X500Name issuerDN = getIssuerDN(xmlCertificate);
        X500Name subjectDN = getSubjectDN(xmlCertificate);
        Time notBefore = getNotBefore(xmlCertificate);
        Time notAfter = getNotAfter(xmlCertificate);
        AlgorithmIdentifier signatureOID = getAlgorithmIdentifier(xmlCertificate);

        Modification modification = xmlCertificate.getModification();

        if (modification != null)
        {
            checkInputData(modification, new ModificationValidator(),
                           "Wrong value for modification in XML certificate with id '" + certificateId + "'.");
        }

        de.mtg.certpathtest.Modification modificationValue =
            Optional.ofNullable(modification).map(mod -> de.mtg.certpathtest.Modification.valueOf(mod.getId()))
                    .orElse(null);

        byte[] userPublicKey = getPublicKey(xmlCertificate, modificationValue);
        byte[] caPublicKey = getIssuerPublicKey(xmlCertificate);

        // START needed for supporting creation of paths
        ObjectCache cache = ObjectCache.getInstance();
        String verifiedBy = xmlCertificate.getVerifiedBy();
        cache.assignIssuerToCertificate(certificateId, verifiedBy);
        // STOP needed for supporting creation of paths

        // START needed for avoiding creating certificates with the same serial number
        cache.addSerialNumber(serialNumber.toString(), certificateId);
        // STOP needed for avoiding creating certificates with the same serial number

        String issuerUniqueID = getIssuerUniqueID(xmlCertificate);
        String subjectUniqueID = getSubjectUniqueID(xmlCertificate);

        SimpleTBSCertificate tbsCertificate = new SimpleTBSCertificate();

        // mandatory fields
        tbsCertificate.setVersion(new ASN1Integer(version));
        tbsCertificate.setSerialNumber(new ASN1Integer(serialNumber));
        tbsCertificate.setSignature(signatureOID);
        tbsCertificate.setIssuer(issuerDN);
        tbsCertificate.setSubject(subjectDN);
        tbsCertificate.setStartDate(notBefore);
        tbsCertificate.setEndDate(notAfter);
        tbsCertificate.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(userPublicKey));

        if (issuerUniqueID != null)
        {
            tbsCertificate.setIssuerUniqueID(new DERBitString(Utils.convertBitString(issuerUniqueID)));
        }

        if (subjectUniqueID != null)
        {
            tbsCertificate.setSubjectUniqueID(new DERBitString(Utils.convertBitString(subjectUniqueID)));
        }

        ArrayList<Extension> extensions = xmlCertificate.getExtensions();

        if (extensions != null)
        {

            for (Extension extension : extensions)
            {

                String oid = extension.getOid();

                if (oid == null || oid.isEmpty())
                {
                    String message = "Missing OID.";
                    Utils.logError(message);
                    throw new IllegalArgumentException(message);
                }

                XMLExtension xmlExtension = null;

                if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId()))
                {
                    xmlExtension = new AuthorityKeyIdentifier(extension, caPublicKey);
                }
                else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()))
                {
                    xmlExtension = new SubjectKeyIdentifier(extension, userPublicKey);
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

                if (tbsCertificate.getExtensions() == null)
                {
                    List<SimpleExtension> simpleExtensions = new ArrayList<SimpleExtension>();
                    tbsCertificate.setExtensions(simpleExtensions);
                }

                tbsCertificate.getExtensions().add(xmlExtension.getSimpleExtension());
            }

        }

        if (modificationValue != null)
        {
            if (de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM);
                tbsCertificate.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.5.29.35.8.9")));
            }
        }

        byte[] rawSignature = getRawSignature(xmlCertificate, tbsCertificate, signatureOID, modificationValue);

        SimpleCertificate simpleCertificate = new SimpleCertificate();

        if (modificationValue != null)
        {
            if (de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.DIFF_SIGN_ALGORITHMS);
                signatureOID = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
                                                                                Utils.getDifferentAlgorithm(signatureOID.getAlgorithm()
                                                                                                                        .getId())));
            }
            else if (de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM);
                signatureOID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.5.29.35.8.9"));
            }
        }

        simpleCertificate.setSignatureAlgorithm(signatureOID);
        simpleCertificate.setTbsCertificate(tbsCertificate);
        simpleCertificate.setSignature(rawSignature);

        encodedValue = simpleCertificate.getEncoded(ASN1Encoding.DER);

        if (modificationValue != null)
        {
            if (de.mtg.certpathtest.Modification.WRONG_DER_ENCODING.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.WRONG_DER_ENCODING);
                encodedValue =
                    calculateWrongDEREncoding(encodedValue, tbsCertificate.getEncoded(), signatureOID, xmlCertificate);
            }
        }
    }

    // private byte[] calculateWrongDEREncoding(byte[] correctCertificate, byte[] tbsCertificate,
    // AlgorithmIdentifier algorithmIdentifier,
    // de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    // throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
    // SignatureException
    // {
    // ByteArrayInputStream bais = new ByteArrayInputStream(correctCertificate);
    // ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
    // DLSequence dlSequence = (DLSequence) asn1InputStream.readObject();
    // asn1InputStream.close();
    // bais.close();
    //
    // int certificateSize = dlSequence.getEncoded().length;
    // int tbsSize = ((DLSequence) dlSequence.getObjectAt(0)).getEncoded().length;
    // int algoIdSize = ((DLSequence) dlSequence.getObjectAt(1)).getEncoded().length;
    // int derSignatureSize = ((DERBitString) dlSequence.getObjectAt(2)).getEncoded().length;
    //
    // int startSize = certificateSize - (tbsSize + algoIdSize + derSignatureSize);
    //
    // byte[] wrongTBSCertificate = Utils.getRandomByteArray(tbsCertificate, 20);
    //
    // PrivateKey privateKey = getSignatureKey(xmlCertificate);
    //
    // Signature signature = Signature.getInstance(algorithmIdentifier.getAlgorithm().toString(), "BC");
    //
    // signature.initSign(privateKey);
    // signature.update(wrongTBSCertificate);
    // byte[] rawSignature = signature.sign();
    //
    // int signatureSize = rawSignature.length;
    //
    // byte[] result = new byte[correctCertificate.length];
    //
    // System.arraycopy(correctCertificate, 0, result, 0, startSize);
    // System.arraycopy(wrongTBSCertificate, 0, result, startSize, tbsSize);
    // System.arraycopy(correctCertificate, startSize + tbsSize, result, startSize + tbsSize, algoIdSize);
    // System.arraycopy(correctCertificate, startSize + tbsSize + algoIdSize, result, startSize + tbsSize + algoIdSize,
    // (derSignatureSize - signatureSize));
    // System.arraycopy(rawSignature, 0, result, startSize + tbsSize + algoIdSize + (derSignatureSize - signatureSize),
    // signatureSize);
    //
    // return result;
    //
    // }

    private byte[] calculateWrongDEREncoding(byte[] correctCertificate, byte[] tbsCertificate,
                                             AlgorithmIdentifier algorithmIdentifier,
                                             de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
                    throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
                    SignatureException
    {

        ByteArrayInputStream bais = new ByteArrayInputStream(correctCertificate);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence dlSequence = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        int certificateSize = dlSequence.getEncoded().length;
        int tbsSize = ((DLSequence) dlSequence.getObjectAt(0)).getEncoded().length;
        int algoIdSize = ((DLSequence) dlSequence.getObjectAt(1)).getEncoded().length;
        int derSignatureSize = ((DERBitString) dlSequence.getObjectAt(2)).getEncoded().length;

        int startSize = certificateSize - (tbsSize + algoIdSize + derSignatureSize);

        byte[] wrongTBS = new byte[tbsCertificate.length];
        System.arraycopy(tbsCertificate, 0, wrongTBS, 0, tbsCertificate.length);
        // //30 82 01 15 30 81 CC A0 03 02 01
        // wrongTBS[3] = (byte) 0x89;
        // wrongTBS[4] = (byte) 0x03;

        // A0 = -96
        if (wrongTBS[3] == -96)
        {
            wrongTBS[3] = (byte) 0x77;
        }

        if (wrongTBS[4] == -96)
        {
            wrongTBS[4] = (byte) 0x77;
        }

        PrivateKey privateKey = getSignatureKey(xmlCertificate);

        Signature signature = Signature.getInstance(algorithmIdentifier.getAlgorithm().toString(), "BC");

        signature.initSign(privateKey);
        signature.update(wrongTBS);
        byte[] rawSignature = signature.sign();

        int signatureSize = rawSignature.length;

        byte[] result = new byte[correctCertificate.length];

        System.arraycopy(correctCertificate, 0, result, 0, startSize);
        System.arraycopy(wrongTBS, 0, result, startSize, tbsSize);
        System.arraycopy(correctCertificate, startSize + tbsSize, result, startSize + tbsSize, algoIdSize);
        System.arraycopy(correctCertificate, startSize + tbsSize + algoIdSize, result, startSize + tbsSize + algoIdSize,
                         (derSignatureSize - signatureSize));
        System.arraycopy(rawSignature, 0, result, startSize + tbsSize + algoIdSize + (derSignatureSize - signatureSize),
                         signatureSize);

        result[3] = (byte) (result[3] + 33);
        result[4] = (byte) 0x03;

        return result;

    }

    public byte[] getEncoded()
    {
        return encodedValue;
    }

    protected static void checkInputData(Object xmlData, ValueValidator valueValidator, String message)
    {

        if (xmlData == null)
        {
            message = message + " Value is empty.";
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }

        if (xmlData instanceof String)
        {
            xmlData = ((String) xmlData).trim();
        }

        boolean result = valueValidator.validate(xmlData);

        if (!result)
        {
            Utils.logError(message);
            throw new IllegalArgumentException(message);
        }
    }

    private BigInteger getSerialNumber(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        String serialNumber = xmlCertificate.getSerialNumber();
        checkInputData(serialNumber, new IntegerValidator(), "Wrong value '" + serialNumber
            + "' for serialNumber in XML certificate with id '" + xmlCertificate.getId() + "'.");
        return new BigInteger(serialNumber);

    }

    private BigInteger getVersion(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        String version = xmlCertificate.getVersion();
        checkInputData(version, new IntegerValidator(), "Wrong value '" + version
            + "' for version in XML certificate with id '" + xmlCertificate.getId() + "'.");
        return new BigInteger(version);

    }

    /**
     *
     * This methods adds certificates to cache
     *
     * @param xmlCertificate
     * @param id
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws DuplicateKeyException
     */
    private byte[] getPublicKey(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate,
                                de.mtg.certpathtest.Modification modification)
                    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
                    DuplicateKeyException
    {
        String id = xmlCertificate.getId().trim();

        PublicKey xmlPublicKey = xmlCertificate.getPublicKey();
        checkInputData(xmlPublicKey, new PublicKeyValidator(),
                       "Wrong value for public key in XML certificate with id '" + id + "'.");

        String type = xmlPublicKey.getType().trim();
        String value = xmlPublicKey.getValue().trim();

        ObjectCache cache = ObjectCache.getInstance();

        if ("raw".equalsIgnoreCase(type))
        {

            PrivateKey privateKey = null;

            StringTokenizer tokenizer = new StringTokenizer(value, "|");

            String publicKeyString = tokenizer.nextToken();
            String privateKeyString = tokenizer.nextToken();

            byte[] rawPublicKey = Base64.decode(publicKeyString);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString));

            try
            {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                privateKey = kf.generatePrivate(privateKeySpec);
            }
            catch (Exception e)
            {
                try
                {
                    KeyFactory kf = KeyFactory.getInstance("EC");
                    privateKey = kf.generatePrivate(privateKeySpec);
                }
                catch (InvalidKeySpecException ikse)
                {
                    Utils.logError("Key is neither RSA nor EC.");
                    logger.debug("", ikse);
                    return null;
                }
            }

            cache.addPrivateKey(id, privateKey);
            cache.addPublicKey(id, rawPublicKey);

            return rawPublicKey;
        }
        else
        {

            KeyPair kp = null;

            StringTokenizer tokenizer = new StringTokenizer(value, ",");

            // holds the algorithm
            tokenizer.nextToken();
            String parameter = tokenizer.nextToken();

            if (value.startsWith("RSA"))
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
                kpg.initialize(Integer.parseInt(parameter), new SecureRandom());
                kp = kpg.generateKeyPair();
            }
            else if (value.startsWith("ECDSA"))
            {
                ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec(parameter);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
                kpg.initialize(ecps);
                kp = kpg.generateKeyPair();
            }
            else if (value.startsWith("ECDH"))
            {
                ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec(parameter);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
                kpg.initialize(ecps);
                kp = kpg.generateKeyPair();
            }
            else
            {
                Utils.logError("Unknown algorithm/parameter '"+value+"'. Cannot create key pair.");
                return null;
            }

            PrivateKey privateKey = kp.getPrivate();
            java.security.PublicKey publicKey = kp.getPublic();

            if (modification != null)
            {
                if (de.mtg.certpathtest.Modification.RSA_LOW_EXPONENT.equals(modification))
                {
                    logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.RSA_LOW_EXPONENT);
                    BigInteger e;
                    BigInteger n;
                    BigInteger d;

                    while (true)
                    {
                        BigInteger p = new BigInteger(1024, 80, new Random());
                        BigInteger q = new BigInteger(1024, 80, new Random());

                        e = new BigInteger("3");
                        n = p.multiply(q);
                        BigInteger phip = p.subtract(BigInteger.ONE);
                        BigInteger phiq = q.subtract(BigInteger.ONE);
                        BigInteger phin = phip.multiply(phiq);

                        try
                        {
                            d = e.modInverse(phin);
                            break;
                        }
                        catch (ArithmeticException ae)
                        {

                        }
                    }

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                    RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);

                    try
                    {
                        publicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);
                        privateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
                    }
                    catch (InvalidKeySpecException ex)
                    {
                        Utils.logError("Exception occurred: " + ex);
                        logger.debug("Stacktrace: ", ex);
                    }
                }
            }

            cache.addPrivateKey(id, privateKey);
            cache.addPublicKey(id, publicKey.getEncoded());

            return publicKey.getEncoded();

        }
    }

    private Time getNotBefore(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        NotBefore notBefore = xmlCertificate.getNotBefore();
        checkInputData(notBefore, new DateValidator(),
                       "Wrong value for notBefore in XML certificate with id '" + xmlCertificate.getId() + "'.");

        String value = notBefore.getValue();

        Time time = Utils.convertValue(value, notBefore.getEncoding());

        return time;

    }

    private Time getNotAfter(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        NotAfter notAfter = xmlCertificate.getNotAfter();
        checkInputData(notAfter, new DateValidator(),
                       "Wrong value for notAfter in XML certificate with id '" + xmlCertificate.getId() + "'.");

        String value = notAfter.getValue();

        Time time = Utils.convertValue(value, notAfter.getEncoding());

        return time;
    }

    private String getIssuerUniqueID(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {

        String issuerUniqueID = xmlCertificate.getIssuerUniqueID();

        if (issuerUniqueID == null)
        {
            return null;
        }

        checkInputData(issuerUniqueID, new BinaryStringValidator(), "Wrong value '" + issuerUniqueID
            + "' for issuerUniqueID in XML certificate with id '" + xmlCertificate.getId() + "'.");

        return issuerUniqueID;

    }

    private String getSubjectUniqueID(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        String subjectUniqueID = xmlCertificate.getSubjectUniqueID();

        if (subjectUniqueID == null)
        {
            return null;
        }

        checkInputData(subjectUniqueID, new BinaryStringValidator(), "Wrong value '" + subjectUniqueID
            + "' for subjectUniqueID in XML certificate with id '" + xmlCertificate.getId() + "'.");

        return subjectUniqueID;

    }

    private X500Name getIssuerDN(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        IssuerDN issuerDN = xmlCertificate.getIssuerDN();
        checkInputData(issuerDN, new DNValidator(),
                       "Wrong value for issuer in XML certificate with id '" + xmlCertificate.getId() + "'.");

        String encoding = issuerDN.getEncoding().trim();
        String value = issuerDN.getValue().trim();

        if ("UTF8".equalsIgnoreCase(encoding))
        {
            return new X500Name(value);
        }
        else if ("PrintableString".equalsIgnoreCase(encoding))
        {

            return Utils.getAsPrintableStringName(value);
        }

        return null;

    }

    private X500Name getSubjectDN(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        SubjectDN subjectDN = xmlCertificate.getSubjectDN();
        checkInputData(subjectDN, new DNValidator(),
                       "Wrong value for subject in XML certificate with id '" + xmlCertificate.getId() + "'.");

        String encoding = subjectDN.getEncoding().trim();
        String value = subjectDN.getValue().trim();

        if ("UTF8".equalsIgnoreCase(encoding))
        {
            return new X500Name(value);
        }
        else if ("PrintableString".equalsIgnoreCase(encoding))
        {

            return Utils.getAsPrintableStringName(value);
        }

        return null;
    }

    private PrivateKey getSignatureKey(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {

        String verifiedBy = xmlCertificate.getVerifiedBy();
        checkInputData(verifiedBy, new PrivateKeyValidator(),
                       "Wrong value for VerifiedBy in XML certificate with id '" + xmlCertificate.getId() + "'.");

        return ObjectCache.getInstance().getPrivateKey(verifiedBy);

    }

    private byte[] getIssuerPublicKey(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {
        String verifiedBy = xmlCertificate.getVerifiedBy();
        return ObjectCache.getInstance().getPublicKey(verifiedBy);
    }

    private AlgorithmIdentifier getAlgorithmIdentifier(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate)
    {

        String signatureOID = xmlCertificate.getSignature();
        checkInputData(signatureOID, new RegExpValidator("(\\d+\\.{1})*\\d+"),
                       "Wrong value for signatureOID in XML certificate with id '" + xmlCertificate.getId() + "'.");

        if (isAlgorithmRSA(signatureOID))
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID), DERNull.INSTANCE);
        }
        else
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID));
        }

    }

    private byte[] getRawSignature(de.mtg.certpathtest.pkiobjects.Certificate xmlCertificate,
                                   SimpleTBSCertificate tbsCertificate, AlgorithmIdentifier algorithmIdentifier,
                                   de.mtg.certpathtest.Modification modification)
                    throws SignatureException, IOException, InvalidKeyException, NoSuchAlgorithmException,
                    NoSuchProviderException, InvalidAlgorithmParameterException
    {

        byte[] tbsPart = tbsCertificate.getEncoded();
        PrivateKey privateKey = getSignatureKey(xmlCertificate);

        ObjectCache objectCache = ObjectCache.getInstance();
        Certificate issuerCertificate = objectCache.getCertificate(xmlCertificate.getVerifiedBy());

        if (issuerCertificate != null)
        {

            try
            {
                Certificate issuerCertCopy = null;
                if (Utils.hasReference(issuerCertificate))
                {
                    issuerCertCopy = Utils.createCompleteCertificateFromReference(issuerCertificate);
                }
                else
                {
                    issuerCertCopy = Utils.cloneCertificate(issuerCertificate);
                }

                de.mtg.certpathtest.Modification modificationValue =
                    Optional.ofNullable(issuerCertCopy.getModification())
                            .map(mod -> de.mtg.certpathtest.Modification.valueOf(mod.getId())).orElse(null);

                if (de.mtg.certpathtest.Modification.RSA_LOW_EXPONENT.equals(modificationValue))
                {
                    logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.RSA_LOW_EXPONENT);
                    return Utils.calculateBleichenbacherSignature(tbsPart, 1,
                                                                  ((RSAPrivateKey) privateKey).getPrivateExponent(),
                                                                  ((RSAPrivateKey) privateKey).getModulus(),
                                                                  algorithmIdentifier.getAlgorithm().toString());
                }

            }
            catch (JAXBException e)
            {
                Utils.logError("Exception occurred: " + e);
                logger.debug("Stacktrace: ", e);
            }
        }

        if (modification != null)
        {
            if (de.mtg.certpathtest.Modification.EMPTY_SIGNATURE.equals(modification))
            {
                logger.info("Applying modificatiion '{}'.", de.mtg.certpathtest.Modification.EMPTY_SIGNATURE);
                return null;
            }
            else if (de.mtg.certpathtest.Modification.WRONG_SIGNATURE.equals(modification))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.WRONG_SIGNATURE);
                Random random = new Random();
                random.nextBytes(tbsPart);
            }
            else if (de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION.equals(modification))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.DUPLICATE_EXTENSION);
            }
        }

        Signature signature = Signature.getInstance(algorithmIdentifier.getAlgorithm().toString(), "BC");

        signature.initSign(privateKey);
        signature.update(tbsPart);
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

}
