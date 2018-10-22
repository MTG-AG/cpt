/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Time;

/**
 * <pre>
 * SingleResponse ::= SEQUENCE {
 * certID                       CertID,
 * certStatus                   CertStatus,
 * thisUpdate                   GeneralizedTime,
 * nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
 * singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
 *
 *
 * CertID ::= SEQUENCE {
 *    hashAlgorithm           AlgorithmIdentifier,
 *    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
 *    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
 *    serialNumber            CertificateSerialNumber }
 * </pre>
 */
public class SimpleSingleResponse extends ASN1Object
{

    private ASN1Sequence certID;
    private ASN1TaggedObject certStatus;
    private Time thisUpdate;
    private ASN1TaggedObject nextUpdate;
    private ASN1TaggedObject singleExtensions;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleSingleResponse(ASN1Sequence seq)
    {
        if (seq.size() == 5)
        {
            certID = ASN1Sequence.getInstance(seq.getObjectAt(0));
            certStatus = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            thisUpdate = Time.getInstance(seq.getObjectAt(2));
            nextUpdate = ASN1TaggedObject.getInstance(seq.getObjectAt(3));
            singleExtensions = ASN1TaggedObject.getInstance(seq.getObjectAt(4));
        }
        else if (seq.size() == 4)
        {
            certID = ASN1Sequence.getInstance(seq.getObjectAt(0));
            certStatus = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            thisUpdate = Time.getInstance(seq.getObjectAt(2));

            ASN1TaggedObject extra = (ASN1TaggedObject) seq.getObjectAt(3);

            if (extra.getTagNo() == 0)
            {
                nextUpdate = ASN1TaggedObject.getInstance(extra, true); // explicit
            }
            else if (extra.getTagNo() == 1)
            {
                singleExtensions = ASN1TaggedObject.getInstance(extra, true); // explicit
            }
        }
        else if (seq.size() == 3)
        {
            certID = ASN1Sequence.getInstance(seq.getObjectAt(0));
            certStatus = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            thisUpdate = Time.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for ocsp response data");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(certID);
        vector.add(certStatus);
        vector.add(thisUpdate);
        if (nextUpdate != null)
        {
            vector.add(nextUpdate);
        }
        if (singleExtensions != null)
        {
            vector.add(singleExtensions);
        }
        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     *
     * @return instance or null
     */
    public static SimpleSingleResponse getInstance(Object obj)
    {
        SimpleSingleResponse cert = null;

        if (obj instanceof SimpleSingleResponse)
        {
            cert = (SimpleSingleResponse) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleSingleResponse(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleSingleResponse()
    {
        // does nothing
    }

    public ASN1Sequence getCertID()
    {
        return certID;
    }

    public void setCertID(ASN1Sequence certID)
    {
        this.certID = certID;
    }

    public ASN1TaggedObject getCertStatus()
    {
        return certStatus;
    }

    public void setCertStatus(ASN1TaggedObject certStatus)
    {
        this.certStatus = certStatus;
    }

    public Time getThisUpdate()
    {
        return thisUpdate;
    }

    public void setThisUpdate(Time thisUpdate)
    {
        this.thisUpdate = thisUpdate;
    }

    public ASN1TaggedObject getNextUpdate()
    {
        return nextUpdate;
    }

    public void setNextUpdate(ASN1TaggedObject nextUpdate)
    {
        this.nextUpdate = nextUpdate;
    }

    public ASN1TaggedObject getSingleExtensions()
    {
        return singleExtensions;
    }

    public void setSingleExtensions(ASN1TaggedObject singleExtensions)
    {
        this.singleExtensions = singleExtensions;
    }
}
