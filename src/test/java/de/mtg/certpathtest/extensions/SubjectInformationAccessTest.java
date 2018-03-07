
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.AuthorityInformationAccess;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectInformationAccess;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.SubjectInformationAccess}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.SubjectInformationAccess SubjectInformationAccess
 *
 *
 */
public class SubjectInformationAccessTest
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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId());
        extension.setType("pretty");
        extension.setValue("https://testurl.de");

        SubjectInformationAccess siae = new SubjectInformationAccess(extension);
        byte[] encoded = siae.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        DLSequence accessDescription = (DLSequence) sequence.getObjectAt(0);
        ASN1ObjectIdentifier accessMethod = (ASN1ObjectIdentifier) accessDescription.getObjectAt(0);
        DERTaggedObject accessLocation = (DERTaggedObject) accessDescription.getObjectAt(1);

        Assert.assertNotNull(accessDescription);
        Assert.assertEquals(2, accessDescription.size());
        Assert.assertEquals("1.3.6.1.5.5.7.48.2", accessMethod.getId());
        Assert.assertEquals(GeneralName.uniformResourceIdentifier, accessLocation.getTagNo());

        DEROctetString name = (DEROctetString) accessLocation.getObject();

        Assert.assertTrue(Arrays.equals("https://testurl.de".getBytes(), name.getOctets()));

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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess.getId());
        extension.setType("pretty");
        extension.setValue("");

        new AuthorityInformationAccess(extension);

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
