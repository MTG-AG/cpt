
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CertificatePolicies CertificatePolicies
 *
 *
 */
public class CertificatePoliciesTest
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

        String correctValue = "1.2.3.4.5, 2.3.4.5.6";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        CertificatePolicies certificatePolicies = new CertificatePolicies(extension);
        byte[] encoded = certificatePolicies.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);

        DLSequence seq = (DLSequence) asn1InputStream.readObject();

        Assert.assertEquals(seq.size(), 2);

        DLSequence firstPolicy = (DLSequence) seq.getObjectAt(0);
        DLSequence secondPolicy = (DLSequence) seq.getObjectAt(1);

        Assert.assertEquals(firstPolicy.size(), 1);
        Assert.assertEquals(secondPolicy.size(), 1);

        ASN1ObjectIdentifier firstPolicyOID = (ASN1ObjectIdentifier) firstPolicy.getObjectAt(0);
        ASN1ObjectIdentifier secondPolicyOID = (ASN1ObjectIdentifier) secondPolicy.getObjectAt(0);

        Assert.assertEquals(firstPolicyOID.getId(), "1.2.3.4.5");
        Assert.assertEquals(secondPolicyOID.getId(), "2.3.4.5.6");

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

        String correctValue = "1.2.3.4.5, A.3.4.5.6";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificatePolicies.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        new CertificatePolicies(extension);

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
