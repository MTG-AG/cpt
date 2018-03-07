
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer CertificateIssuer
 *
 *
 */
public class CertificateIssuerTest
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

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId());
        extension.setType("pretty");
        extension.setValue("CN=Test, C=DE|UTF8");

        CertificateIssuer certifiacteIssuer = new CertificateIssuer(extension);
        byte[] encoded = certifiacteIssuer.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);

        Assert.assertEquals(GeneralName.directoryName, taggedObject.getTagNo());

        DERSequence dnSequence = (DERSequence) taggedObject.getObject();

        Assert.assertEquals(2, dnSequence.size());

        DERSet cn = (DERSet) dnSequence.getObjectAt(0);
        DERSet c = (DERSet) dnSequence.getObjectAt(1);
        DERSequence cnSeq = (DERSequence) cn.getObjectAt(0);
        DERSequence cSeq = (DERSequence) c.getObjectAt(0);

        Assert.assertEquals(2, cnSeq.size());
        Assert.assertEquals(2, cSeq.size());

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

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId());
        extension.setType("pretty");
        extension.setValue("CN=Test");

        new CertificateIssuer(extension);

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
