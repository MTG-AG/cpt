/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;

import de.mtg.security.asn1.x509.common.ExtUtil;
import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.security.asn1.x509.util.Util;

/**
 * A TBSCertificate structure.
 *
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *     version           [ 0 ] Version DEFAULT v1(0),
 *     serialNumber            CertificateSerialNumber,
 *     signature               AlgorithmIdentifier,
 *     issuer                  Name,
 *     validity                Validity,
 *     subject                 Name,
 *     subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *     issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *     subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *     extensions        [ 3 ] Extensions OPTIONAL
 * }
 * </pre>
 */
public class SimpleTBSCertificate extends ASN1Object
{
    private ASN1Integer version;
    private ASN1Integer serialNumber;
    private AlgorithmIdentifier signature;
    private X500Name issuer;
    private Time startDate;
    private Time endDate;
    private X500Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private DERBitString issuerUniqueID;
    private DERBitString subjectUniqueID;
    private List<SimpleExtension> extensions;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleTBSCertificate(ASN1Sequence seq)
    {
        int index = 0;

        // version is tagged and optional with default v1
        ASN1Encodable entry = seq.getObjectAt(0);
        if (entry instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject) entry;
            if (tagged.getTagNo() != 0)
            {

            }
            version = ASN1Integer.getInstance(tagged, true);
            ++index;
        }

        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(index++));

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));

        issuer = X500Name.getInstance(seq.getObjectAt(index++));

        ASN1Sequence validity = ASN1Sequence.getInstance(seq.getObjectAt(index++));
        startDate = Time.getInstance(validity.getObjectAt(0));
        endDate = Time.getInstance(validity.getObjectAt(1));

        subject = X500Name.getInstance(seq.getObjectAt(index++));

        subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(index++));

        if (index < seq.size())
        {
            ASN1TaggedObject extra = (ASN1TaggedObject) seq.getObjectAt(index);

            if (extra.getTagNo() == 1)
            {
                issuerUniqueID = DERBitString.getInstance(extra, false); // implicit
                ++index;
            }
        }

        if (index < seq.size())
        {
            ASN1TaggedObject extra = (ASN1TaggedObject) seq.getObjectAt(index);

            if (extra.getTagNo() == 2)
            {
                subjectUniqueID = DERBitString.getInstance(extra, false); // implicit
                ++index;
            }
        }

        if (index < seq.size())
        {
            ASN1TaggedObject extra = (ASN1TaggedObject) seq.getObjectAt(index);

            if (extra.getTagNo() == 3)
            {
                ASN1Sequence exts = ASN1Sequence.getInstance(extra, true);
                extensions = ExtUtil.collectExtensions(exts);
                ++index;
            }
        }

        if (index < seq.size())
        {

        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        if (version != null)
        {
            vector.add(new DERTaggedObject(true, 0, version));
        }

        vector.add(serialNumber);
        vector.add(signature);
        vector.add(issuer);

        ASN1EncodableVector validity = new ASN1EncodableVector();
        validity.add(startDate);
        validity.add(endDate);
        vector.add(new DERSequence(validity));

        vector.add(subject);

        vector.add(subjectPublicKeyInfo);

        if (issuerUniqueID != null)
        {
            vector.add(new DERTaggedObject(false, 1, issuerUniqueID));
        }

        if (subjectUniqueID != null)
        {
            vector.add(new DERTaggedObject(false, 2, subjectUniqueID));
        }

        if (extensions != null)
        {
            ASN1Sequence extSeq = ExtUtil.concatenateExtensions(extensions);
            vector.add(new DERTaggedObject(true, 3, extSeq));
        }

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static SimpleTBSCertificate getInstance(Object obj)
    {
        SimpleTBSCertificate tbsCert = null;

        if (obj instanceof SimpleTBSCertificate)
        {
            tbsCert = (SimpleTBSCertificate) obj;
        }
        else if (obj != null)
        {
            tbsCert = new SimpleTBSCertificate(ASN1Sequence.getInstance(obj));
        }

        return tbsCert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleTBSCertificate()
    {
        // does nothing
    }

    /**
     * Returns the version if it is set.
     * <p>
     * The value null means default v1(0).
     * <p>
     * The value 0 means v1(0).
     * <p>
     * The value 2 means v3(2).
     *
     * @return version or null
     */
    public ASN1Integer getVersion()
    {
        return version;
    }

    /**
     * Sets the version.
     * <p>
     * If set to null then nothing will be encoded and default v1(0) is assumed.
     * <p>
     * If set to 0 then this value will be explicitly encoded.
     *
     * @param version may be null
     */
    public void setVersion(ASN1Integer version)
    {
        this.version = version;
    }

    /**
     * @return 1 for v1(0), 2 for v2(1), 3 for v3(2), ...
     */
    public int getVersionNumber()
    {
        return (version == null) ? 1 : (version.getValue().intValue() + 1);
    }

    /**
     * Encodes 1 as null (default v1(0)), 2 as v2(1), 3 as v3(2), ...
     *
     * @param vNum
     */
    public void setVersionNumber(int vNum)
    {
        version = (vNum == 1) ? null : new ASN1Integer(vNum - 1);
    }

    /**
     * @return serialNumber
     */
    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(ASN1Integer serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    /**
     * @return signature
     */
    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    /**
     * @param signature the signature to set
     */
    public void setSignature(AlgorithmIdentifier signature)
    {
        this.signature = signature;
    }

    /**
     * @return issuer
     */
    public X500Name getIssuer()
    {
        return issuer;
    }

    /**
     * @param issuer the issuer to set
     */
    public void setIssuer(X500Name issuer)
    {
        this.issuer = issuer;
    }

    /**
     * @return startDate
     */
    public Time getStartDate()
    {
        return startDate;
    }

    /**
     * @param startDate the startDate to set
     */
    public void setStartDate(Time startDate)
    {
        this.startDate = startDate;
    }

    /**
     * @return endDate
     */
    public Time getEndDate()
    {
        return endDate;
    }

    /**
     * @param endDate the endDate to set
     */
    public void setEndDate(Time endDate)
    {
        this.endDate = endDate;
    }

    /**
     * @return subject
     */
    public X500Name getSubject()
    {
        return subject;
    }

    /**
     * @param subject the subject to set
     */
    public void setSubject(X500Name subject)
    {
        this.subject = subject;
    }

    /**
     * @return subjectPublicKeyInfo
     */
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    /**
     * @param subjectPublicKeyInfo the subjectPublicKeyInfo to set
     */
    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }

    /**
     * Builds the public key object from the subjectPublicKeyInfo.
     *
     * @return publicKey
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public PublicKey getPublicKey() throws IOException, GeneralSecurityException
    {
        return Util.buildPublicKey(subjectPublicKeyInfo);
    }

    /**
     * Builds the subjectPublicKeyInfo from the given X.509 public key.
     *
     * @param publicKey
     */
    public void setPublicKey(PublicKey publicKey)
    {
        subjectPublicKeyInfo = Util.buildSubjectPublicKeyInfo(publicKey);
    }

    /**
     * @return issuerUniqueID
     */
    public DERBitString getIssuerUniqueID()
    {
        return issuerUniqueID;
    }

    /**
     * @param issuerUniqueID
     */
    public void setIssuerUniqueID(DERBitString issuerUniqueID)
    {
        this.issuerUniqueID = issuerUniqueID;
    }

    /**
     * @return subjectUniqueID
     */
    public DERBitString getSubjectUniqueID()
    {
        return subjectUniqueID;
    }

    /**
     * @param subjectUniqueID
     */
    public void setSubjectUniqueID(DERBitString subjectUniqueID)
    {
        this.subjectUniqueID = subjectUniqueID;
    }

    /**
     * @return extensions
     */
    public List<SimpleExtension> getExtensions()
    {
        return extensions;
    }

    /**
     * @param extensions
     */
    public void setExtensions(List<SimpleExtension> extensions)
    {
        this.extensions = extensions;
    }

}
