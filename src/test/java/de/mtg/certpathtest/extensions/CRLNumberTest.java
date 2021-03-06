
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CRLNumber;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CRLNumber}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CRLNumber CRLNumber
 */
public class CRLNumberTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        BigInteger value = new BigInteger("-123");

        Extension extension = new Extension();
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.cRLNumber.getId());
        extension.setType("pretty");
        extension.setValue(value.toString());

        CRLNumber crlNumber = new CRLNumber(extension);
        byte[] encoded = crlNumber.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            ASN1Integer asn1Integer = (ASN1Integer) asn1InputStream.readObject();
            Assertions.assertEquals(0, asn1Integer.getValue().compareTo(value));
            Assertions.assertNotNull(asn1Integer.getValue());
        }
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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.cRLNumber.getId());
        extension.setType("pretty");
        extension.setValue("-3D");

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new CRLNumber(extension));

    }

}
