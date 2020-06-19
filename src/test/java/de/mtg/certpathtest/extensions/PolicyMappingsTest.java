
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints;
import de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings PolicyMappings
 */
public class PolicyMappingsTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        String correctValue = "1.2.3.7,1.4.5.6|1.6.8.7,1.2.7.8";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.policyMappings.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        PolicyMappings policyMappings = new PolicyMappings(extension);
        byte[] encoded = policyMappings.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence seq = (DLSequence) asn1InputStream.readObject();
            Assertions.assertEquals(2, seq.size());

            DLSequence firstMapping = (DLSequence) seq.getObjectAt(0);
            DLSequence secondMapping = (DLSequence) seq.getObjectAt(1);

            Assertions.assertEquals(2, firstMapping.size());
            Assertions.assertEquals(2, secondMapping.size());

            ASN1ObjectIdentifier firstMappingIssuerPolicy = (ASN1ObjectIdentifier) firstMapping.getObjectAt(0);
            ASN1ObjectIdentifier firstMappingSubjectPolicy = (ASN1ObjectIdentifier) firstMapping.getObjectAt(1);

            ASN1ObjectIdentifier secondMappingIssuerPolicy = (ASN1ObjectIdentifier) secondMapping.getObjectAt(0);
            ASN1ObjectIdentifier secondMappingSubjectPolicy = (ASN1ObjectIdentifier) secondMapping.getObjectAt(1);

            Assertions.assertEquals("1.2.3.7", firstMappingIssuerPolicy.getId());
            Assertions.assertEquals("1.4.5.6", firstMappingSubjectPolicy.getId());
            Assertions.assertEquals("1.6.8.7", secondMappingIssuerPolicy.getId());
            Assertions.assertEquals("1.2.7.8", secondMappingSubjectPolicy.getId());
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

        String wrongValue = "1,true";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.policyMappings.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new PolicyMappings(extension));
    }

    /**
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testAgainstHighLevel() throws Exception
    {

        String correctValue = "true, 0";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);
        BasicConstraints basicConstraints = new BasicConstraints(extension);

        org.bouncycastle.asn1.x509.BasicConstraints highLevelBasicConstraints =
                        new org.bouncycastle.asn1.x509.BasicConstraints(0);

        Assertions.assertTrue(Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "true, 20";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(20);
        Assertions.assertTrue(Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "false, 2";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(false);
        Assertions.assertTrue(!Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "false";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(false);
        // false is always explicitly encoded
        Assertions.assertTrue(!Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

    }

}
