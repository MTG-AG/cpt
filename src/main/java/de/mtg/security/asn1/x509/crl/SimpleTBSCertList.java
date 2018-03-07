/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.crl;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;

import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.security.asn1.x509.common.ExtUtil;

/**
 * Simple TBSCertList object.
 *
 * <pre>
 * TBSCertList ::= SEQUENCE {
 *     version                 Version OPTIONAL,
 *                                 -- if present, MUST be v2
 *     signature               AlgorithmIdentifier,
 *     issuer                  Name,
 *     thisUpdate              Time,
 *     nextUpdate              Time OPTIONAL,
 *     revokedCertificates     SEQUENCE OF SEQUENCE  {
 *         userCertificate         CertificateSerialNumber,
 *         revocationDate          Time,
 *         crlEntryExtensions      Extensions OPTIONAL
 *                                     -- if present, version MUST be v2
 *     } OPTIONAL,
 *     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
 *                                 -- if present, version MUST be v2
 * }
 * </pre>
 */
public class SimpleTBSCertList extends ASN1Object
{
    private ASN1Integer version;
    private AlgorithmIdentifier signature;
    private X500Name issuer;
    private Time thisUpdate;
    private Time nextUpdate;
    private List<RevokedCertificate> revokedCertificates;
    private List<SimpleExtension> crlExtensions;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleTBSCertList(ASN1Sequence seq)
    {
        if (seq.size() < 3 || seq.size() > 7)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        int index = 0;

        // version is optional
        if (seq.getObjectAt(index) instanceof ASN1Integer)
        {
            version = ASN1Integer.getInstance(seq.getObjectAt(index++));
        }

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        issuer = X500Name.getInstance(seq.getObjectAt(index++));
        thisUpdate = Time.getInstance(seq.getObjectAt(index++));

        // nextUpdate is optional
        if (index < seq.size())
        {
            ASN1Encodable entry = seq.getObjectAt(index);
            if (entry instanceof ASN1UTCTime || entry instanceof ASN1GeneralizedTime || entry instanceof Time)
            {
                nextUpdate = Time.getInstance(entry);
                ++index;
            }
        }

        // revokedCertificates is optional
        if (index < seq.size())
        {
            ASN1Encodable entry = seq.getObjectAt(index);
            if (!(entry instanceof ASN1TaggedObject))
            {
                ASN1Sequence certSeq = ASN1Sequence.getInstance(entry);
                ++index;

                revokedCertificates = new ArrayList<RevokedCertificate>(certSeq.size());
                for (int i = 0; i < certSeq.size(); ++i)
                {
                    revokedCertificates.add(RevokedCertificate.getInstance(certSeq.getObjectAt(i)));
                }
            }
        }

        // crlExtensions is optional and tagged
        if (index < seq.size())
        {
            ASN1Encodable entry = seq.getObjectAt(index);
            if (entry instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
                ++index;

                if (taggedEntry.getTagNo() != 0)
                {

                }
                ASN1Sequence exts = ASN1Sequence.getInstance(taggedEntry, true);
                crlExtensions = ExtUtil.collectExtensions(exts);
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
            vector.add(version);
        }

        vector.add(signature);
        vector.add(issuer);
        vector.add(thisUpdate);

        if (nextUpdate != null)
        {
            vector.add(nextUpdate);
        }

        if (revokedCertificates != null)
        {
            ASN1EncodableVector certs = new ASN1EncodableVector();

            for (RevokedCertificate cert : revokedCertificates)
            {
                certs.add(cert);
            }

            vector.add(new DERSequence(certs));
        }

        if (crlExtensions != null)
        {
            ASN1Sequence extSeq = ExtUtil.concatenateExtensions(crlExtensions);
            vector.add(new DERTaggedObject(true, 0, extSeq));
        }

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static SimpleTBSCertList getInstance(Object obj)
    {
        SimpleTBSCertList list = null;

        if (obj instanceof SimpleTBSCertList)
        {
            list = (SimpleTBSCertList) obj;
        }
        else if (obj != null)
        {
            list = new SimpleTBSCertList(ASN1Sequence.getInstance(obj));
        }

        return list;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleTBSCertList()
    {
        // does nothing
    }

    /**
     * @return the version
     */
    public ASN1Integer getVersion()
    {
        return version;
    }

    /**
     * @param version the version to set
     */
    public void setVersion(ASN1Integer version)
    {
        this.version = version;
    }

    /**
     * @return the signature
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
     * @return the issuer
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
     * @return the thisUpdate
     */
    public Time getThisUpdate()
    {
        return thisUpdate;
    }

    /**
     * @param thisUpdate the thisUpdate to set
     */
    public void setThisUpdate(Time thisUpdate)
    {
        this.thisUpdate = thisUpdate;
    }

    /**
     * @return the nextUpdate
     */
    public Time getNextUpdate()
    {
        return nextUpdate;
    }

    /**
     * @param nextUpdate the nextUpdate to set
     */
    public void setNextUpdate(Time nextUpdate)
    {
        this.nextUpdate = nextUpdate;
    }

    /**
     * Returns the revoked certificates.
     * <p>
     * The list does not get copied.
     *
     * @return the revokedCertificates or null
     */
    public List<RevokedCertificate> getRevokedCertificates()
    {
        return revokedCertificates;
    }

    /**
     * Sets the revoked certificates.
     * <p>
     * The list does not get copied.
     *
     * @param revokedCertificates the revokedCertificates to set
     */
    public void setRevokedCertificates(List<RevokedCertificate> revokedCertificates)
    {
        this.revokedCertificates = revokedCertificates;
    }

    /**
     * @return the crlExtensions
     */
    public List<SimpleExtension> getCrlExtensions()
    {
        return crlExtensions;
    }

    /**
     * @param crlExtensions the crlExtensions to set
     */
    public void setCrlExtensions(List<SimpleExtension> crlExtensions)
    {
        this.crlExtensions = crlExtensions;
    }

}
