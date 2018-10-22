/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.ocsp;

import de.mtg.security.asn1.x509.cert.SimpleTBSCertificate;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * <pre>
 * OCSPResponse ::= SEQUENCE {
 * responseStatus         OCSPResponseStatus,
 * responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 *
 *
 * ResponseBytes ::=       SEQUENCE {
 * responseType   OBJECT IDENTIFIER,
 * response       OCTET STRING }
 * </pre>
 */
public class SimpleOCSPResponse extends ASN1Object
{

    private ASN1Enumerated responseStatus;
    private ASN1TaggedObject responseBytes;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleOCSPResponse(ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            responseStatus = ASN1Enumerated.getInstance(seq.getObjectAt(0));
            responseBytes = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
        }
        else if (seq.size() == 1)
        {
            responseStatus = ASN1Enumerated.getInstance(seq.getObjectAt(0));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for an ocsp response");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(responseStatus);
        if (responseBytes != null)
        {
            vector.add(responseBytes);
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
    public static SimpleOCSPResponse getInstance(Object obj)
    {
        SimpleOCSPResponse cert = null;

        if (obj instanceof SimpleOCSPResponse)
        {
            cert = (SimpleOCSPResponse) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleOCSPResponse(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleOCSPResponse()
    {
        // does nothing
    }

    public ASN1Enumerated getResponseStatus()
    {
        return responseStatus;
    }

    public void setResponseStatus(ASN1Enumerated responseStatus)
    {
        this.responseStatus = responseStatus;
    }

    public ASN1TaggedObject getResponseBytes()
    {
        return responseBytes;
    }

    public void setResponseBytes(ASN1TaggedObject responseBytes)
    {
        this.responseBytes = responseBytes;
    }
}
