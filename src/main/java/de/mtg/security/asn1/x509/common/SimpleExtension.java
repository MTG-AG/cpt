/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.common;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;

/**
 * Extension.
 * <p>
 * The default critical = FALSE is explicitly encoded.
 * <p>
 * Set critical = null to prevent encoding.
 *
 * <pre>
 * Extension ::= SEQUENCE {
 *     extnId     EXTENSION.&amp;id ({ExtensionSet}),
 *     critical   BOOLEAN DEFAULT FALSE,
 *     extnValue  OCTET STRING }
 * </pre>
 * <p>
 * The OIDs defined in {@link Extension} may be used.
 */
public class SimpleExtension extends ASN1Object
{
    private ASN1ObjectIdentifier extnId;
    private ASN1Boolean critical;
    private byte[] extnValueOctets;

    public SimpleExtension()
    {

    }

    /**
     * Constructor for generation from sequence.
     *
     * @param seq
     */
    private SimpleExtension(ASN1Sequence seq)
    {
        if (seq.size() == 2 || seq.size() == 3)
        {
            int index = 0;
            this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(index++));
            if (seq.size() == 3)
            {
                this.critical = ASN1Boolean.getInstance(seq.getObjectAt(index++));
            }
            this.extnValueOctets = ASN1OctetString.getInstance(seq.getObjectAt(index++)).getOctets();
        }
        else
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    /**
     * Builds sequence from existing components.
     * <p>
     * critical is encoded if available.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(extnId);

        if (critical != null)
        {
            vector.add(critical);
        }

        vector.add(new DEROctetString(extnValueOctets));

        return new DERSequence(vector);
    }

    /**
     * Builds and fills instance from object.
     *
     * @param obj
     * @return instance or null
     */
    public static SimpleExtension getInstance(Object obj)
    {
        SimpleExtension extension = null;

        if (obj instanceof SimpleExtension)
        {
            extension = (SimpleExtension) obj;
        }
        else if (obj != null)
        {
            extension = new SimpleExtension(ASN1Sequence.getInstance(obj));
        }

        return extension;
    }

    /**
     * Constructor.
     * <p>
     * Use the set-methods and encode.
     *
     * @param extnId OID of extension
     */
    public SimpleExtension(ASN1ObjectIdentifier extnId)
    {
        this.extnId = extnId;
    }

    /**
     * @return the extnId
     */
    public ASN1ObjectIdentifier getExtnId()
    {
        return extnId;
    }

    /**
     * @param extnId OID of extension
     */
    public void setExtnId(ASN1ObjectIdentifier extnId)
    {
        this.extnId = extnId;
    }

    /**
     * @return the critical
     */
    public ASN1Boolean getCritical()
    {
        return critical;
    }

    /**
     * @param critical the critical to set
     */
    public void setCritical(ASN1Boolean critical)
    {
        this.critical = critical;
    }

    /**
     * Sets critical = ASN1Boolean.TRUE or null.
     * <p>
     * ASN1Boolean.FALSE is default.
     *
     * @param critical the critical to set
     */
    public void setCritical(boolean critical)
    {
        this.critical = critical ? ASN1Boolean.TRUE : null;
    }

    /**
     * Returns the extnValueOctets attribute.
     *
     * @return The extnValueOctets
     */
    public byte[] getExtnValueOctets()
    {
        return extnValueOctets;
    }

    /**
     * Sets the extnValueOctets attribute.
     *
     * @param extnValueOctets The extnValueOctets to set
     */
    public void setExtnValueOctets(byte[] extnValueOctets)
    {
        this.extnValueOctets = extnValueOctets;
    }

    /**
     * Sets the extnValue from ASN.1 object.
     *
     * @param asn1Object
     * @throws IOException
     */
    public void setExtnValueFromObject(ASN1Object asn1Object) throws IOException
    {
        this.extnValueOctets = (asn1Object != null) ? asn1Object.getEncoded(ASN1Encoding.DER) : null;
    }

}
