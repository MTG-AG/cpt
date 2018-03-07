
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints;
import de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.PolicyMappings PolicyMappings
 *
 *
 */
public class PolicyMappingsTest
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

        String correctValue = "1.2.3.7,1.4.5.6|1.6.8.7,1.2.7.8";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.policyMappings.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        PolicyMappings policyMappings = new PolicyMappings(extension);
        byte[] encoded = policyMappings.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence seq = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        bais.close();

        Assert.assertEquals(2, seq.size());

        DLSequence firstMapping = (DLSequence) seq.getObjectAt(0);
        DLSequence secondMapping = (DLSequence) seq.getObjectAt(1);

        Assert.assertEquals(2, firstMapping.size());
        Assert.assertEquals(2, secondMapping.size());

        ASN1ObjectIdentifier firstMappingIssuerPolicy = (ASN1ObjectIdentifier) firstMapping.getObjectAt(0);
        ASN1ObjectIdentifier firstMappingSubjectPolicy = (ASN1ObjectIdentifier) firstMapping.getObjectAt(1);

        ASN1ObjectIdentifier secondMappingIssuerPolicy = (ASN1ObjectIdentifier) secondMapping.getObjectAt(0);
        ASN1ObjectIdentifier secondMappingSubjectPolicy = (ASN1ObjectIdentifier) secondMapping.getObjectAt(1);


        Assert.assertEquals("1.2.3.7", firstMappingIssuerPolicy.getId());
        Assert.assertEquals("1.4.5.6", firstMappingSubjectPolicy.getId());
        Assert.assertEquals("1.6.8.7", secondMappingIssuerPolicy.getId());
        Assert.assertEquals("1.2.7.8", secondMappingSubjectPolicy.getId());



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

        String wrongValue = "1,true";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.policyMappings.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        new PolicyMappings(extension);

    }

    /**
     *
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

        Assert.assertTrue(Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "true, 20";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(20);
        Assert.assertTrue(Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "false, 2";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(false);
        Assert.assertTrue(!Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

        // New case

        correctValue = "false";
        extension.setValue(correctValue);
        basicConstraints = new BasicConstraints(extension);

        highLevelBasicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(false);
        // false is always explicitly encoded
        Assert.assertTrue(!Arrays.equals(basicConstraints.getEncoded(), highLevelBasicConstraints.getEncoded()));

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
