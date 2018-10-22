/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Time;

/**
 *
 * <pre>
 * ResponseData ::= SEQUENCE {
 * version              [0] EXPLICIT Version DEFAULT v1,
 * responderID              ResponderID,
 * producedAt               GeneralizedTime,
 * responses                SEQUENCE OF SingleResponse,
 * responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 */
public class SimpleResponseData extends ASN1Object
{

    private ASN1TaggedObject version;
    private ASN1TaggedObject responderID;
    private Time producedAt;
    private ASN1Sequence responses;
    private ASN1TaggedObject responseExtensions;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleResponseData(ASN1Sequence seq)
    {
        if (seq.size() == 5)
        {
            version = ASN1TaggedObject.getInstance(seq.getObjectAt(0));
            responderID = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            producedAt = Time.getInstance(seq.getObjectAt(2));
            responses = ASN1Sequence.getInstance(seq.getObjectAt(3));
            responseExtensions = ASN1TaggedObject.getInstance(seq.getObjectAt(4));
        }
        else if (seq.size() == 4)
        {
            version = ASN1TaggedObject.getInstance(seq.getObjectAt(0));
            responderID = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
            producedAt = Time.getInstance(seq.getObjectAt(2));
            responses = ASN1Sequence.getInstance(seq.getObjectAt(3));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for OCSP response data");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(version);
        vector.add(responderID);
        vector.add(producedAt);
        vector.add(responses);
        if (responseExtensions != null)
        {
            vector.add(responseExtensions);
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
    public static SimpleResponseData getInstance(Object obj)
    {
        SimpleResponseData cert = null;

        if (obj instanceof SimpleResponseData)
        {
            cert = (SimpleResponseData) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleResponseData(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleResponseData()
    {
        // does nothing
    }

    public ASN1TaggedObject getVersion()
    {
        return version;
    }

    public void setVersion(ASN1TaggedObject version)
    {
        this.version = version;
    }

    public ASN1TaggedObject getResponderID()
    {
        return responderID;
    }

    public void setResponderID(ASN1TaggedObject responderID)
    {
        this.responderID = responderID;
    }

    public Time getProducedAt()
    {
        return producedAt;
    }

    public void setProducedAt(Time producedAt)
    {
        this.producedAt = producedAt;
    }

    public ASN1Sequence getResponses()
    {
        return responses;
    }

    public void setResponses(ASN1Sequence responses)
    {
        this.responses = responses;
    }

    public ASN1TaggedObject getResponseExtensions()
    {
        return responseExtensions;
    }

    public void setResponseExtensions(ASN1TaggedObject responseExtensions)
    {
        this.responseExtensions = responseExtensions;
    }
}
