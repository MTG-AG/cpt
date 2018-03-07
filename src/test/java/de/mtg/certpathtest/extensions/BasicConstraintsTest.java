
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints BasicConstraints
 *
 *
 */
public class BasicConstraintsTest
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

        String correctValue = "true, 1";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        BasicConstraints basicConstraints = new BasicConstraints(extension);
        byte[] encoded = basicConstraints.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);

        DLSequence seq = (DLSequence) asn1InputStream.readObject();

        ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);
        ASN1Integer pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

        Assert.assertEquals(isCA.isTrue(), true);
        Assert.assertEquals(pathLengthConstraints.getValue().intValue(), 1);
        asn1InputStream.close();
        bais.close();

        // New case

        correctValue = "false, 12";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        bais = new ByteArrayInputStream(encoded);
        asn1InputStream = new ASN1InputStream(bais);

        seq = (DLSequence) asn1InputStream.readObject();

        isCA = (ASN1Boolean) seq.getObjectAt(0);
        pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

        Assert.assertEquals(isCA.isTrue(), false);
        Assert.assertEquals(pathLengthConstraints.getValue().intValue(), 12);
        asn1InputStream.close();
        bais.close();

        // New case

        correctValue = "true, -2";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        bais = new ByteArrayInputStream(encoded);
        asn1InputStream = new ASN1InputStream(bais);

        seq = (DLSequence) asn1InputStream.readObject();

        isCA = (ASN1Boolean) seq.getObjectAt(0);
        pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

        Assert.assertEquals(isCA.isTrue(), true);
        Assert.assertEquals(pathLengthConstraints.getValue().intValue(), -2);
        asn1InputStream.close();
        bais.close();

        // New case

        correctValue = "true";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        bais = new ByteArrayInputStream(encoded);
        asn1InputStream = new ASN1InputStream(bais);

        seq = (DLSequence) asn1InputStream.readObject();

        isCA = (ASN1Boolean) seq.getObjectAt(0);

        Assert.assertEquals(isCA.isTrue(), true);
        Assert.assertEquals(seq.size(), 1);
        asn1InputStream.close();
        bais.close();

        // New case

        correctValue = "false";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        bais = new ByteArrayInputStream(encoded);
        asn1InputStream = new ASN1InputStream(bais);

        seq = (DLSequence) asn1InputStream.readObject();

        isCA = (ASN1Boolean) seq.getObjectAt(0);

        Assert.assertEquals(isCA.isTrue(), false);
        Assert.assertEquals(seq.size(), 1);
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

        String wrongValue = "1,true";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        new BasicConstraints(extension);

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
