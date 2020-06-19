
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectDirectoryAttributes;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence sequence = (DLSequence) asn1InputStream.readObject();
            DLSequence secondSequence = (DLSequence) sequence.getObjectAt(0);

            Assertions.assertNotNull(sequence);
            Assertions.assertEquals(1, sequence.size());
            Assertions.assertEquals(2, secondSequence.size());
        }
    }

    /**
     *
     * Tests whether this extension cannot be created from a pretty representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testIncorrect()
    {

        Extension extension = new Extension();
        extension.setCritical("false");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId());
        extension.setType("pretty");
        extension.setValue("This should be empty");

        Assertions.assertThrows(UnsupportedOperationException.class, () -> new SubjectDirectoryAttributes(extension));

    }

}
