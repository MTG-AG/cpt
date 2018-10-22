/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * ResponseBytes ::=       SEQUENCE {
 * responseType   OBJECT IDENTIFIER,
 * response       OCTET STRING }
 * </pre>
 */
public class SimpleResponseBytes extends ASN1Object
{

    private ASN1ObjectIdentifier responseType;
    private ASN1OctetString response;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleResponseBytes(ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            responseType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            response = DEROctetString.getInstance(seq.getObjectAt(1));
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

        vector.add(responseType);
        vector.add(response);

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     *
     * @return instance or null
     */
    public static SimpleResponseBytes getInstance(Object obj)
    {
        SimpleResponseBytes cert = null;

        if (obj instanceof SimpleResponseBytes)
        {
            cert = (SimpleResponseBytes) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleResponseBytes(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleResponseBytes()
    {
        // does nothing
    }

    public ASN1ObjectIdentifier getResponseType()
    {
        return responseType;
    }

    public void setResponseType(ASN1ObjectIdentifier responseType)
    {
        this.responseType = responseType;
    }

    public ASN1OctetString getResponse()
    {
        return response;
    }

    public void setResponse(ASN1OctetString response)
    {
        this.response = response;
    }
}
