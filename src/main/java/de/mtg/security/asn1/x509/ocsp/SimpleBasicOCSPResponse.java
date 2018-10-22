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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * <pre>
 * BasicOCSPResponse    ::= SEQUENCE {
 * tbsResponseData      ResponseData,
 * signatureAlgorithm   AlgorithmIdentifier,
 * signature            BIT STRING,
 * certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 */
public class SimpleBasicOCSPResponse extends ASN1Object
{

    private ASN1Sequence tbsResponseData;
    private AlgorithmIdentifier signatureAlgorithm;
    private DERBitString signature;
    private ASN1TaggedObject certs;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleBasicOCSPResponse(ASN1Sequence seq)
    {
        if (seq.size() == 4)
        {
            tbsResponseData = ASN1Sequence.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            signature = DERBitString.getInstance(seq.getObjectAt(2));
            certs = ASN1TaggedObject.getInstance(seq.getObjectAt(3));
        }
        else if (seq.size() == 3)
        {
            tbsResponseData = ASN1Sequence.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            signature = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for an ocsp basic response");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(tbsResponseData);
        vector.add(signatureAlgorithm);
        vector.add(signature);
        if (certs != null) {
            vector.add(certs);
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
    public static SimpleBasicOCSPResponse getInstance(Object obj)
    {
        SimpleBasicOCSPResponse cert = null;

        if (obj instanceof SimpleBasicOCSPResponse)
        {
            cert = (SimpleBasicOCSPResponse) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleBasicOCSPResponse(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleBasicOCSPResponse()
    {
        // does nothing
    }

    public ASN1Sequence getTbsResponseData()
    {
        return tbsResponseData;
    }

    public void setTbsResponseData(ASN1Sequence tbsResponseData)
    {
        this.tbsResponseData = tbsResponseData;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public DERBitString getSignature()
    {
        return signature;
    }

    public void setSignature(DERBitString signature)
    {
        this.signature = signature;
    }

    public ASN1TaggedObject getCerts()
    {
        return certs;
    }

    public void setCerts(ASN1TaggedObject certs)
    {
        this.certs = certs;
    }
}
