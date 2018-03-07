/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.cert;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * An X509Certificate structure.
 *
 * <pre>
 * Certificate ::= SEQUENCE {
 *     tbsCertificate      TBSCertificate,
 *     signatureAlgorithm  AlgorithmIdentifier,
 *     signature           BIT STRING
 * }
 * </pre>
 */
public class SimpleCertificate extends ASN1Object
{
    private SimpleTBSCertificate tbsCertificate;
    private AlgorithmIdentifier signatureAlgorithm;
    private DERBitString signature;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleCertificate(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            tbsCertificate = SimpleTBSCertificate.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            signature = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else if (seq.size() == 2)
        {
            tbsCertificate = SimpleTBSCertificate.getInstance(seq.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for a certificate");
        }
    }

    /**
     * Builds sequence from existing components.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(tbsCertificate);
        vector.add(signatureAlgorithm);
        if (signature != null)
        {
            vector.add(signature);
        }
        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static SimpleCertificate getInstance(Object obj)
    {
        SimpleCertificate cert = null;

        if (obj instanceof SimpleCertificate)
        {
            cert = (SimpleCertificate) obj;
        }
        else if (obj != null)
        {
            cert = new SimpleCertificate(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public SimpleCertificate()
    {
        // does nothing
    }

    /**
     * @return the tbsCertificate
     */
    public SimpleTBSCertificate getTbsCertificate()
    {
        return tbsCertificate;
    }

    /**
     * @param tbsCertificate the tbsCertificate to set
     */
    public void setTbsCertificate(SimpleTBSCertificate tbsCertificate)
    {
        this.tbsCertificate = tbsCertificate;
    }

    /**
     * @return the bytes to be signed
     * @throws CertificateEncodingException
     */
    public byte[] getToBeSigned() throws CertificateEncodingException
    {
        byte[] tbs = null;

        if (tbsCertificate != null)
        {
            try
            {
                tbs = tbsCertificate.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException ex)
            {
                throw new CertificateEncodingException(ex);
            }
        }

        return tbs;
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
     * @return the object identifier for the signature.
     */
    public String getSigAlgOID()
    {
        String oid = null;
        if (signatureAlgorithm != null)
        {
            oid = signatureAlgorithm.getAlgorithm().getId();
        }
        return oid;
    }

    /**
     * @return the signature parameters, or null if there aren't any.
     */
    public byte[] getSigAlgParams()
    {
        byte[] params = null;
        if (signatureAlgorithm != null && signatureAlgorithm.getParameters() != null)
        {
            try
            {
                return signatureAlgorithm.getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            }
            catch (IOException ex)
            {
                // should not happen
            }
        }
        return params;
    }

    /**
     * @return the signature
     */
    public DERBitString getSignature()
    {
        return signature;
    }

    /**
     * @param signature the signature as bit string
     */
    public void setSignature(DERBitString signature)
    {
        this.signature = signature;
    }

    /**
     * @param signature the signature as byte array
     */
    public void setSignature(byte[] signature)
    {
        this.signature = (signature != null) ? new DERBitString(signature) : null;
    }

}
