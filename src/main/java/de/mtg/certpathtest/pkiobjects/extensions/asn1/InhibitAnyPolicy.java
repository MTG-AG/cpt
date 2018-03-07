
package de.mtg.certpathtest.pkiobjects.extensions.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 *
 * Low level ASN.1 based implementation of the inhibit anyPolicy certificate extension.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.14">RFC 5280</a>
 *
 *      <pre>
 * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 *      </pre>
 *
 */
public class InhibitAnyPolicy extends ASN1Object
{
    private BigInteger inhinitAnyPolicy;

    /**
     *
     * Constructs a newly allocated InhibitAnyPolicy object.
     *
     * @param inhinitAnyPolicy the number of certificates to be skipped. This is the value of the <code>SkipCerts</code>
     *            element.
     */
    public InhibitAnyPolicy(BigInteger inhinitAnyPolicy)
    {
        this.inhinitAnyPolicy = inhinitAnyPolicy;
    }

    /**
     *
     * Returns the value of the <code>SkipCerts</code> element if this extension.
     *
     * @return the number of certificates to be skipped.
     */
    public BigInteger getInhinitAnyPolicy()
    {
        return inhinitAnyPolicy;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(inhinitAnyPolicy);
    }

}
