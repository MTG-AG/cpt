
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.DeltaCRLIndicator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.DeltaCRLIndicator}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.DeltaCRLIndicator DeltaCRLIndicator
 */
public class DeltaCRLIndicatorTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        BigInteger value = new BigInteger("985462388");

        Extension extension = new Extension();
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator.getId());
        extension.setType("pretty");
        extension.setValue(value.toString());

        DeltaCRLIndicator deltaCrlIndicator = new DeltaCRLIndicator(extension);
        byte[] encoded = deltaCrlIndicator.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        ASN1Integer asn1Integer = (ASN1Integer) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        Assertions.assertEquals(0, asn1Integer.getValue().compareTo(value));
        Assertions.assertNotNull(asn1Integer.getValue());

    }

    /**
     * Tests whether this extension cannot be created from a wrong pretty representation and a proper exception is
     * thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testIncorrect()
    {

        Extension extension = new Extension();
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator.getId());
        extension.setType("pretty");
        extension.setValue("This should be an integer");

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new DeltaCRLIndicator(extension));

    }

}
