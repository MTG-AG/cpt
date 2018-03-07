/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.crl;

import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Time;

import de.mtg.security.asn1.x509.common.SimpleExtension;
import de.mtg.security.asn1.x509.common.ExtUtil;

/**
 * RevokedCertificate or CRLEntry of TBSCertList.
 *
 * <pre>
 * RevokedCertificate ::= SEQUENCE {
 *     userCertificate     CertificateSerialNumber,
 *     revocationDate      Time,
 *     crlEntryExtensions  Extensions OPTIONAL
 * }
 * </pre>
 */
public class RevokedCertificate extends ASN1Object
{
    private ASN1Integer userCertificate;
    private Time revocationDate;
    private List<SimpleExtension> crlEntryExtensions;

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private RevokedCertificate(ASN1Sequence seq)
    {
        if (seq.size() == 2 || seq.size() == 3)
        {
            userCertificate = ASN1Integer.getInstance(seq.getObjectAt(0));
            revocationDate = Time.getInstance(seq.getObjectAt(1));

            if (seq.size() == 3)
            {
                ASN1Sequence extensions = ASN1Sequence.getInstance(seq.getObjectAt(2));
                crlEntryExtensions = ExtUtil.collectExtensions(extensions);
            }
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

        vector.add(userCertificate);
        vector.add(revocationDate);

        if (crlEntryExtensions != null)
        {
            vector.add(ExtUtil.concatenateExtensions(crlEntryExtensions));
        }

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static RevokedCertificate getInstance(Object obj)
    {
        RevokedCertificate cert = null;

        if (obj instanceof RevokedCertificate)
        {
            cert = (RevokedCertificate) obj;
        }
        else if (obj != null)
        {
            cert = new RevokedCertificate(ASN1Sequence.getInstance(obj));
        }

        return cert;
    }

    /**
     * Constructor of empty object.
     * <p>
     * Use the set-methods and encode.
     */
    public RevokedCertificate()
    {
        // does nothing
    }

    /**
     * @return the userCertificate
     */
    public ASN1Integer getUserCertificate()
    {
        return userCertificate;
    }

    /**
     * @param userCertificate
     *            the userCertificate to set
     */
    public void setUserCertificate(ASN1Integer userCertificate)
    {
        this.userCertificate = userCertificate;
    }

    /**
     * @return the revocationDate
     */
    public Time getRevocationDate()
    {
        return revocationDate;
    }

    /**
     * @param revocationDate
     *            the revocationDate to set
     */
    public void setRevocationDate(Time revocationDate)
    {
        this.revocationDate = revocationDate;
    }

    /**
     * @return the crlEntryExtensions
     */
    public List<SimpleExtension> getCrlEntryExtensions()
    {
        return crlEntryExtensions;
    }

    /**
     * @param crlEntryExtensions
     *            the crlEntryExtensions to set
     */
    public void setCrlEntryExtensions(List<SimpleExtension> crlEntryExtensions)
    {
        this.crlEntryExtensions = crlEntryExtensions;
    }

}
