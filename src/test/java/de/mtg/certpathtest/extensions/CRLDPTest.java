
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CRLDP;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CRLDP}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CRLDP CRLDP
 *
 *
 */
public class CRLDPTest
{

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {

    }

    /**
     *
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

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        DLSequence distributionPoint = (DLSequence) sequence.getObjectAt(0);
        DERTaggedObject distributionPointName = (DERTaggedObject) distributionPoint.getObjectAt(0);
        Assert.assertEquals(distributionPointName.getTagNo(), 0);
        DERTaggedObject taggedGeneralNames = (DERTaggedObject) distributionPointName.getObject();
        Assert.assertEquals(taggedGeneralNames.getTagNo(), 0);
        DLSequence generalNames = (DLSequence) taggedGeneralNames.getObject();

        DERTaggedObject firstUri = (DERTaggedObject) generalNames.getObjectAt(0);
        DERTaggedObject secondUri = (DERTaggedObject) generalNames.getObjectAt(1);
        Assert.assertEquals(firstUri.getTagNo(), 6);
        Assert.assertEquals(secondUri.getTagNo(), 6);

        DEROctetString firstUriValue = (DEROctetString) firstUri.getObject();
        DEROctetString secondUriValue = (DEROctetString) secondUri.getObject();

        Assert.assertEquals(new String(firstUriValue.getOctets()), firstComponent);
        Assert.assertEquals(new String(secondUriValue.getOctets()), secondComponent);

        asn1InputStream.close();
        bais.close();

    }

    /**
     *
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test(expected = WrongPKIObjectException.class)
    public void testIncorrect() throws Exception
    {

        String wrongValue = "";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        CRLDP crldp = new CRLDP(extension);
        byte[] encoded = crldp.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);
        DEROctetString octetString = (DEROctetString) taggedObject.getObject();
        asn1InputStream.close();
        bais.close();

        Assert.assertNotNull(octetString);
        Assert.assertEquals(octetString.getOctets().length, 20);

    }

    /**
     *
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @After
    public void tearDown() throws Exception
    {

    }

}
