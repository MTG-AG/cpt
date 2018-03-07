
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.Modification;
import de.mtg.certpathtest.pkiobjects.NextUpdate;
import de.mtg.certpathtest.pkiobjects.RevocationDate;
import de.mtg.certpathtest.pkiobjects.RevokedCertificate;
import de.mtg.certpathtest.pkiobjects.ThisUpdate;
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
import de.mtg.certpathtest.validators.DNValidator;
import de.mtg.certpathtest.validators.DateValidator;
import de.mtg.certpathtest.validators.IntegerValidator;
import de.mtg.certpathtest.validators.ModificationValidator;
import de.mtg.certpathtest.validators.PrivateKeyValidator;
import de.mtg.certpathtest.validators.RegExpValidator;
import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.security.asn1.x509.crl.SimpleCertificateList;
import de.mtg.security.asn1.x509.crl.SimpleTBSCertList;

public class TestToolCRL
{
    private static Logger logger = LoggerFactory.getLogger(TestToolCRL.class);

    private byte[] encodedValue = null;

    /**
     *
     * Constructs a newly allocated TestToolCRL object.
     *
     * <ul>
     * <li>It extracts the data from this xmlCertificate.</li>
     * <li>It verifies that these data are correct</li>
     * </ul>
     */
    public TestToolCRL(de.mtg.certpathtest.pkiobjects.CRL xmlCRL) throws Exception
    {

        String certificateId = xmlCRL.getId();

        BigInteger version = getVersion(xmlCRL);
        X500Name issuerDN = getIssuerDN(xmlCRL);
        Time thisUpdate = getThisUpdate(xmlCRL);
        Time nextUpdate = getNextUpdate(xmlCRL);
        AlgorithmIdentifier signatureOID = getAlgorithmIdentifier(xmlCRL);

        Modification modification = xmlCRL.getModification();

        if (modification != null)
        {
            TestToolCertificate.checkInputData(modification, new ModificationValidator(),
                                               "Wrong value for modification in XML CRL with id '" + certificateId
                                                   + "'.");
        }

        de.mtg.certpathtest.Modification modificationValue =
            Optional.ofNullable(modification).map(mod -> de.mtg.certpathtest.Modification.valueOf(mod.getId()))
                    .orElse(null);

        SimpleTBSCertList tbsCRL = new SimpleTBSCertList();

        // mandatory fields
        tbsCRL.setVersion(new ASN1Integer(version));
        tbsCRL.setSignature(signatureOID);
        tbsCRL.setIssuer(issuerDN);
        tbsCRL.setThisUpdate(thisUpdate);
        tbsCRL.setNextUpdate(nextUpdate);

        byte[] issuerPublicKey = getIssuerPublicKey(xmlCRL);

        ArrayList<Extension> extensions = xmlCRL.getExtensions();

        if (extensions != null)
        {

            for (Extension extension : extensions)
            {

                String oid = extension.getOid();

                if (oid == null || oid.isEmpty())
                {
                    String message = "Missing OID in CRL extension.";
                    Utils.logError(message);
                    throw new IllegalArgumentException(message);
                }

                XMLExtension xmlExtension = null;

                if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId()))
                {
                    xmlExtension = new AuthorityKeyIdentifier(extension, issuerPublicKey);
                }
                else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()))
                {
                    String type = extension.getType().trim();

                    if (!"raw".equalsIgnoreCase(type))
                    {
                        Utils.logError("Only the type raw is allowed for the Subject Key Identifier when used in CRLs. Will not add this extension.");
                    }
                    else
                    {
                        xmlExtension = new SubjectKeyIdentifier(extension, issuerPublicKey);
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

                if (tbsCRL.getCrlExtensions() == null)
                {
                    List<SimpleExtension> simpleExtensions = new ArrayList<SimpleExtension>();
                    tbsCRL.setCrlExtensions(simpleExtensions);
                }

                // xmlExtension maybe null if not raw subject key identifier
                if (xmlExtension != null)
                {
                    tbsCRL.getCrlExtensions().add(xmlExtension.getSimpleExtension());
                }
            }

        }

        // handling revoked certificates start
        ArrayList<RevokedCertificate> revokedCertificates = xmlCRL.getRevokedCertificates();

        if (revokedCertificates != null)
        {

            for (RevokedCertificate revokedCertificate : revokedCertificates)
            {

                logger.debug("Revoked Certificate: " + revokedCertificate);

                String certificateRefId = revokedCertificate.getRefid();

                if (certificateRefId == null || certificateRefId.isEmpty())
                {
                    String message = "Missing id for revoked certificate.";
                    Utils.logError(message);
                    throw new IllegalArgumentException(message);
                }

                byte[] rawCert = ObjectCache.getInstance().getRawCertificate(certificateRefId);

                ByteArrayInputStream bais = new ByteArrayInputStream(rawCert);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
                bais.close();

                BigInteger serialNumber = cert.getSerialNumber();

                Time revocationDate = getRevocationDate(revokedCertificate);

                de.mtg.security.asn1.x509.crl.RevokedCertificate asn1RevokedCertificate =
                    new de.mtg.security.asn1.x509.crl.RevokedCertificate();
                asn1RevokedCertificate.setUserCertificate(new ASN1Integer(serialNumber));
                asn1RevokedCertificate.setRevocationDate(revocationDate);

                ArrayList<Extension> crlEntryExtensions = revokedCertificate.getExtensions();

                if (crlEntryExtensions != null)
                {

                    for (Extension crlEntryExtension : crlEntryExtensions)
                    {

                        String oid = crlEntryExtension.getOid();

                        if (oid == null || oid.isEmpty())
                        {
                            String message = "Missing OID in CRL entry extension.";
                            Utils.logError(message);
                            throw new IllegalArgumentException(message);
                        }

                        XMLExtension xmlExtension = null;

                        if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId()))
                        {
                            String type = crlEntryExtension.getType().trim();

                            if (!"raw".equalsIgnoreCase(type))
                            {
                                Utils.logError("Only the type raw is allowed for the Authority Key Identifier when used in CRL Entries. Will not add this extension.");
                            }
                            else
                            {
                                xmlExtension = new AuthorityKeyIdentifier(crlEntryExtension, issuerPublicKey);
                            }
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId()))
                        {
                            String type = crlEntryExtension.getType().trim();

                            if (!"raw".equalsIgnoreCase(type))
                            {
                                Utils.logError("Only the type raw is allowed for the Subject Key Identifier when used in CRL Entries. Will not add this extension.");
                            }
                            else
                            {
                                xmlExtension = new SubjectKeyIdentifier(crlEntryExtension, issuerPublicKey);
                            }
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.keyUsage.getId()))
                        {
                            xmlExtension = new KeyUsage(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId()))
                        {
                            xmlExtension = new CertificatePolicies(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId()))
                        {
                            xmlExtension = new BasicConstraints(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.policyMappings.getId()))
                        {
                            xmlExtension = new PolicyMappings(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName.getId()))
                        {
                            xmlExtension = new SubjectOrIssuerAlternativeName(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName.getId()))
                        {
                            xmlExtension = new SubjectOrIssuerAlternativeName(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId()))
                        {
                            xmlExtension = new SubjectDirectoryAttributes(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.nameConstraints.getId()))
                        {
                            xmlExtension = new NameConstraints(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.policyConstraints.getId()))
                        {
                            xmlExtension = new PolicyConstraints(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage.getId()))
                        {
                            xmlExtension = new ExtendedKeyUsage(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId()))
                        {
                            xmlExtension = new CRLDP(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.inhibitAnyPolicy.getId()))
                        {
                            xmlExtension = new InhibitAnyPolicy(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.freshestCRL.getId()))
                        {
                            xmlExtension = new CRLDP(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId()))
                        {
                            xmlExtension = new AuthorityInformationAccess(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess.getId()))
                        {
                            xmlExtension = new SubjectInformationAccess(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.cRLNumber.getId()))
                        {
                            xmlExtension = new CRLNumber(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator.getId()))
                        {
                            xmlExtension = new DeltaCRLIndicator(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint.getId()))
                        {
                            xmlExtension = new IssuingDistributionPoint(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.reasonCode.getId()))
                        {
                            xmlExtension = new ReasonCode(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.invalidityDate.getId()))
                        {
                            xmlExtension = new InvalidityDate(crlEntryExtension);
                        }
                        else if (oid.equals(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId()))
                        {
                            xmlExtension = new CertificateIssuer(crlEntryExtension);
                        }
                        else
                        {
                            xmlExtension = new UnknownExtension(crlEntryExtension);
                        }

                        if (asn1RevokedCertificate.getCrlEntryExtensions() == null)
                        {
                            List<SimpleExtension> simpleExtensions = new ArrayList<SimpleExtension>();
                            asn1RevokedCertificate.setCrlEntryExtensions(simpleExtensions);
                        }

                        // xmlExtension maybe null if not raw subject or issuer key identifier
                        if (xmlExtension != null)
                        {
                            asn1RevokedCertificate.getCrlEntryExtensions().add(xmlExtension.getSimpleExtension());
                        }
                    }
                }

                if (tbsCRL.getRevokedCertificates() == null)
                {
                    List<de.mtg.security.asn1.x509.crl.RevokedCertificate> existentRevokedCertificates =
                        new ArrayList<de.mtg.security.asn1.x509.crl.RevokedCertificate>();
                    tbsCRL.setRevokedCertificates(existentRevokedCertificates);
                }

                tbsCRL.getRevokedCertificates().add(asn1RevokedCertificate);

            }
        }

        // handling revoked certificates end

        if (modificationValue != null)
        {
            if (de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.UNKNOWN_SIGN_ALGORITHM);
                tbsCRL.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.5.29.35.8.9")));
            }
        }

        byte[] rawSignature = getRawSignature(xmlCRL, tbsCRL, signatureOID, modificationValue);

        SimpleCertificateList simpleCRL = new SimpleCertificateList();

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

        simpleCRL.setSignatureAlgorithm(signatureOID);
        simpleCRL.setTbsCertList(tbsCRL);
        simpleCRL.setSignatureValue(rawSignature);

        encodedValue = simpleCRL.getEncoded(ASN1Encoding.DER);

        if (modificationValue != null)
        {
            if (de.mtg.certpathtest.Modification.WRONG_DER_ENCODING.equals(modificationValue))
            {
                logger.info("Applying modification '{}'.", de.mtg.certpathtest.Modification.WRONG_DER_ENCODING);
                encodedValue = calculateWrongDEREncoding(encodedValue, tbsCRL.getEncoded(), signatureOID, xmlCRL);
            }
        }

        // store CRL Distribution Point for this CRL in cache for future use
        storeCRLLocation(xmlCRL);
    }

    private byte[] calculateWrongDEREncoding(byte[] correctCertificate, byte[] tbsCRL,
                                             AlgorithmIdentifier algorithmIdentifier,
                                             de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
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

        byte[] wrongTBS = new byte[tbsCRL.length];
        System.arraycopy(tbsCRL, 0, wrongTBS, 0, tbsCRL.length);
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

        PrivateKey privateKey = getSignatureKey(xmlCRL);

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

    private void storeCRLLocation(de.mtg.certpathtest.pkiobjects.CRL xmlCRL) throws DuplicateKeyException
    {
        String location = xmlCRL.getLocation();
        ObjectCache cache = ObjectCache.getInstance();

        if (location != null)
        {
            location = location.trim();

            StringTokenizer tokenizer = new StringTokenizer(location, "|");

            while (tokenizer.hasMoreTokens())
            {
                String crldp = tokenizer.nextToken();
                if (crldp.startsWith("http://"))
                {
                    cache.addHTTPCRLDP(crldp, Utils.getCRLId(xmlCRL));
                }
                else if (crldp.startsWith("ldap://"))
                {
                    cache.addLDAPCRLDP(crldp, Utils.getCRLId(xmlCRL));
                }
                else
                {
                    throw new IllegalArgumentException(
                                                       "Wrong value for Location in XML CRL with id '" + xmlCRL.getId()
                                                           + "'. It should start either with http:// or ldap://.");
                }

            }

        }

    }

    private BigInteger getVersion(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {
        String version = xmlCRL.getVersion();
        TestToolCertificate.checkInputData(version, new IntegerValidator(), "Wrong value '" + version
            + "' for version in XML CRL with id '" + xmlCRL.getId() + "'.");
        return new BigInteger(version);

    }

    private Time getThisUpdate(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {
        ThisUpdate thisUpdate = xmlCRL.getThisUpdate();
        TestToolCertificate.checkInputData(thisUpdate, new DateValidator(),
                                           "Wrong value for thisUpdate in XML CRL with id '" + xmlCRL.getId() + "'.");

        String value = thisUpdate.getValue();

        Time time = Utils.convertValue(value, thisUpdate.getEncoding());

        return time;

    }

    private Time getNextUpdate(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {
        NextUpdate nextUpdate = xmlCRL.getNextUpdate();

        if (nextUpdate == null)
        {
            return null;
        }
        TestToolCertificate.checkInputData(nextUpdate, new DateValidator(),
                                           "Wrong value for notAfter in XML CRL with id '" + xmlCRL.getId() + "'.");

        String value = nextUpdate.getValue();

        Time time = Utils.convertValue(value, nextUpdate.getEncoding());

        return time;
    }

    private Time getRevocationDate(RevokedCertificate revokedCertificate)
    {
        RevocationDate revocationDate = revokedCertificate.getRevocationDate();

        TestToolCertificate.checkInputData(revocationDate, new DateValidator(),
                                           "Wrong value for revocationDate in XML CRL.");

        String value = revocationDate.getValue();

        Time time = Utils.convertValue(value, revocationDate.getEncoding());

        return time;
    }

    private X500Name getIssuerDN(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {
        IssuerDN issuerDN = xmlCRL.getIssuerDN();
        TestToolCertificate.checkInputData(issuerDN, new DNValidator(),
                                           "Wrong value for issuer in XML CRL with id '" + xmlCRL.getId() + "'.");

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

    private PrivateKey getSignatureKey(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {

        String verifiedBy = xmlCRL.getVerifiedBy();
        verifiedBy = verifiedBy.trim();
        TestToolCertificate.checkInputData(verifiedBy, new PrivateKeyValidator(),
                                           "Wrong value for VerifiedBy in XML CRL with id '" + xmlCRL.getId() + "'.");

        return ObjectCache.getInstance().getPrivateKey(verifiedBy);

    }

    private AlgorithmIdentifier getAlgorithmIdentifier(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {

        String signatureOID = xmlCRL.getSignature();
        TestToolCertificate.checkInputData(signatureOID, new RegExpValidator("(\\d+\\.{1})*\\d+"),
                                           "Wrong value for signatureOID in XML CRL with id '" + xmlCRL.getId() + "'.");

        if (isAlgorithmRSA(signatureOID))
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID), DERNull.INSTANCE);
        }
        else
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(signatureOID));
        }

    }

    private byte[] getRawSignature(de.mtg.certpathtest.pkiobjects.CRL xmlCRL, SimpleTBSCertList tbsCertList,
                                   AlgorithmIdentifier algorithmIdentifier,
                                   de.mtg.certpathtest.Modification modification)
                    throws SignatureException, IOException, InvalidKeyException, NoSuchAlgorithmException,
                    NoSuchProviderException, InvalidAlgorithmParameterException
    {

        byte[] tbsPart = tbsCertList.getEncoded();
        PrivateKey privateKey = getSignatureKey(xmlCRL);

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

    private byte[] getIssuerPublicKey(de.mtg.certpathtest.pkiobjects.CRL xmlCRL)
    {

        String verifiedBy = xmlCRL.getVerifiedBy();
        verifiedBy = verifiedBy.trim();

        return ObjectCache.getInstance().getPublicKey(verifiedBy);

    }

}
