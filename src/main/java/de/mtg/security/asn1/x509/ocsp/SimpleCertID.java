/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;

/**
 * <pre>
 * CertID ::= SEQUENCE {
 *    hashAlgorithm           AlgorithmIdentifier,
 *    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
 *    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
 *    serialNumber            CertificateSerialNumber }
 * </pre>
 */
public class SimpleCertID extends ASN1Object
{

    private AlgorithmIdentifier hashAlgorithm;
    private ASN1OctetString issuerNameHash;
    private ASN1OctetString issuerKeyHash;
    private ASN1Integer serialNumber;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleCertID(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            issuerNameHash = DEROctetString.getInstance(seq.getObjectAt(1));
            issuerKeyHash = DEROctetString.getInstance(seq.getObjectAt(2));
            serialNumber = ASN1Integer.getInstance(seq.getObjectAt(3));
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

        vector.add(hashAlgorithm);
        vector.add(issuerNameHash);
        vector.add(issuerKeyHash);
        vector.add(serialNumber);

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     *
     * @return instance or null
     */
    public static SimpleCertID getInstance(Object obj)
    {
        SimpleCertID cert = null;

        if (obj instanceof SimpleCertID)
        {
            cert = (SimpleCertID) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleCertID(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleCertID()
    {
        // does nothing
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(AlgorithmIdentifier hashAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
    }

    public ASN1OctetString getIssuerNameHash()
    {
        return issuerNameHash;
    }

    public void setIssuerNameHash(ASN1OctetString issuerNameHash)
    {
        this.issuerNameHash = issuerNameHash;
    }

    public ASN1OctetString getIssuerKeyHash()
    {
        return issuerKeyHash;
    }

    public void setIssuerKeyHash(ASN1OctetString issuerKeyHash)
    {
        this.issuerKeyHash = issuerKeyHash;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public void setSerialNumber(ASN1Integer serialNumber)
    {
        this.serialNumber = serialNumber;
    }
}
