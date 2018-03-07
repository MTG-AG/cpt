
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DLSequence;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectDirectoryAttributes;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.SubjectDirectoryAttributes}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.SubjectDirectoryAttributes SubjectDirectoryAttributes
 *
 *
 */
public class SubjectDirectoryAttributesTest
{

    private String base64EncodedValue = "BBwwGjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB";

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
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId());
        extension.setType("raw");
        extension.setValue(base64EncodedValue);

        SubjectDirectoryAttributes sdae = new SubjectDirectoryAttributes(extension);
        byte[] encoded = sdae.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        DLSequence secondSequence = (DLSequence)sequence.getObjectAt(0);

        Assert.assertNotNull(sequence);
        Assert.assertEquals(1, sequence.size());
        Assert.assertEquals(2, secondSequence.size());

    }

    /**
     *
     * Tests whether this extension cannot be created from a pretty representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testIncorrect() throws Exception
    {

        Extension extension = new Extension();
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId());
        extension.setType("pretty");
        extension.setValue("This should be empty");

        new SubjectDirectoryAttributes(extension);

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
