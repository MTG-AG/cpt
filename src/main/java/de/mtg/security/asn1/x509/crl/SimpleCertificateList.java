/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.crl;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Simple CertificateList or CRL.
 *
 * <pre>
 * CertificateList ::= SEQUENCE {
 *     tbsCertList         TBSCertList,
 *     signatureAlgorithm  AlgorithmIdentifier,
 *     signatureValue      BIT STRING
 * }
 * </pre>
 */
public class SimpleCertificateList extends ASN1Object
{
    SimpleTBSCertList tbsCertList;
    AlgorithmIdentifier signatureAlgorithm;
    DERBitString signatureValue;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleCertificateList(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            tbsCertList = SimpleTBSCertList.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            signatureValue = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else if (seq.size() == 2)
        {
            tbsCertList = SimpleTBSCertList.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            // signatureValue = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for CertificateList");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(tbsCertList);
        vector.add(signatureAlgorithm);
        if (signatureValue != null)
        {
            vector.add(signatureValue);
        }

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static SimpleCertificateList getInstance(Object obj)
    {
        SimpleCertificateList list = null;

        if (obj instanceof SimpleCertificateList)
        {
            list = (SimpleCertificateList) obj;
        }
        else if (obj != null)
        {
            list = new SimpleCertificateList(ASN1Sequence.getInstance(obj));
        }

        return list;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleCertificateList()
    {
        // does nothing
    }

    /**
     * @return the tbsCertList
     */
    public SimpleTBSCertList getTbsCertList()
    {
        return tbsCertList;
    }

    /**
     * @param tbsCertList the tbsCertList to set
     */
    public void setTbsCertList(SimpleTBSCertList tbsCertList)
    {
        this.tbsCertList = tbsCertList;
    }

    /**
     * @return the signatureAlgorithm
     */
    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the signatureValue
     */
    public DERBitString getSignatureValue()
    {
        return signatureValue;
    }

    /**
     * @param signatureValue the signatureValue as bit string
     */
    public void setSignatureValue(DERBitString signatureValue)
    {
        this.signatureValue = signatureValue;
    }

    /**
     * @param signatureValue the signatureValue as byte array
     */
    public void setSignatureValue(byte[] signatureValue)
    {
        this.signatureValue = (signatureValue != null) ? new DERBitString(signatureValue) : null;
    }

}
