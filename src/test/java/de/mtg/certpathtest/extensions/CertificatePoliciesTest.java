
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies CertificatePolicies
 */
public class CertificatePoliciesTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        String correctValue = "1.2.3.4.5, 2.3.4.5.6";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        CertificatePolicies certificatePolicies = new CertificatePolicies(extension);
        byte[] encoded = certificatePolicies.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {

            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            Assertions.assertEquals(seq.size(), 2);

            DLSequence firstPolicy = (DLSequence) seq.getObjectAt(0);
            DLSequence secondPolicy = (DLSequence) seq.getObjectAt(1);

            Assertions.assertEquals(firstPolicy.size(), 1);
            Assertions.assertEquals(secondPolicy.size(), 1);

            ASN1ObjectIdentifier firstPolicyOID = (ASN1ObjectIdentifier) firstPolicy.getObjectAt(0);
            ASN1ObjectIdentifier secondPolicyOID = (ASN1ObjectIdentifier) secondPolicy.getObjectAt(0);

            Assertions.assertEquals(firstPolicyOID.getId(), "1.2.3.4.5");
            Assertions.assertEquals(secondPolicyOID.getId(), "2.3.4.5.6");
        }

    }

    /**
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testIncorrect() throws Exception
    {

        String correctValue = "1.2.3.4.5, A.3.4.5.6";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new CertificatePolicies(extension));
    }

}
