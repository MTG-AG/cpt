
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CRLDP;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CRLDP}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CRLDP CRLDP
 */
public class CRLDPTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        String firstComponent = "https://localhost";
        String secondComponent = "https://foreignhost";

        String correctValue = firstComponent + "|" + secondComponent;

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        CRLDP akie = new CRLDP(extension);
        byte[] encoded = akie.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence sequence = (DLSequence) asn1InputStream.readObject();
            DLSequence distributionPoint = (DLSequence) sequence.getObjectAt(0);
            DERTaggedObject distributionPointName = (DERTaggedObject) distributionPoint.getObjectAt(0);
            Assertions.assertEquals(distributionPointName.getTagNo(), 0);
            DERTaggedObject taggedGeneralNames = (DERTaggedObject) distributionPointName.getObject();
            Assertions.assertEquals(taggedGeneralNames.getTagNo(), 0);
            DLSequence generalNames = (DLSequence) taggedGeneralNames.getObject();

            DERTaggedObject firstUri = (DERTaggedObject) generalNames.getObjectAt(0);
            DERTaggedObject secondUri = (DERTaggedObject) generalNames.getObjectAt(1);
            Assertions.assertEquals(firstUri.getTagNo(), 6);
            Assertions.assertEquals(secondUri.getTagNo(), 6);

            DEROctetString firstUriValue = (DEROctetString) firstUri.getObject();
            DEROctetString secondUriValue = (DEROctetString) secondUri.getObject();

            Assertions.assertEquals(new String(firstUriValue.getOctets()), firstComponent);
            Assertions.assertEquals(new String(secondUriValue.getOctets()), secondComponent);
        }
    }

    /**
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testIncorrect()
    {

        String wrongValue = "";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new CRLDP(extension));

    }

}
