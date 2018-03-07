
package de.mtg.certpathtest.pkiobjects.extensions.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class DeltaCRLIndicator extends ASN1Object
{
    private BigInteger deltaCRLIndicator;

    public DeltaCRLIndicator(BigInteger deltaCRLIndicator)
    {
        this.deltaCRLIndicator = deltaCRLIndicator;
    }

    public BigInteger getDeltaCRLIndicator()
    {
        return deltaCRLIndicator;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(deltaCRLIndicator);
    }

}
