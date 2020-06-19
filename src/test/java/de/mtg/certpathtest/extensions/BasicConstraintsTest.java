
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.BasicConstraints BasicConstraints
 */
public class BasicConstraintsTest
{

    /**
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

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded); ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {

            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);
            ASN1Integer pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

            Assertions.assertEquals(isCA.isTrue(), true);
            Assertions.assertEquals(pathLengthConstraints.getValue().intValue(), 1);
        }

        correctValue = "false, 12";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded); ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);
            ASN1Integer pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

            Assertions.assertEquals(isCA.isTrue(), false);
            Assertions.assertEquals(pathLengthConstraints.getValue().intValue(), 12);

        }

        // New case

        correctValue = "true, -2";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded); ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);
            ASN1Integer pathLengthConstraints = (ASN1Integer) seq.getObjectAt(1);

            Assertions.assertEquals(isCA.isTrue(), true);
            Assertions.assertEquals(pathLengthConstraints.getValue().intValue(), -2);
        }

        // New case

        correctValue = "true";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded); ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);

            Assertions.assertEquals(isCA.isTrue(), true);
            Assertions.assertEquals(seq.size(), 1);
        }

        // New case

        correctValue = "false";
        extension.setValue(correctValue);

        basicConstraints = new BasicConstraints(extension);
        encoded = basicConstraints.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded); ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence seq = (DLSequence) asn1InputStream.readObject();

            ASN1Boolean isCA = (ASN1Boolean) seq.getObjectAt(0);

            Assertions.assertEquals(isCA.isTrue(), false);
            Assertions.assertEquals(seq.size(), 1);
        }

    }

    /**
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testIncorrect()
    {
        String wrongValue = "1,true";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new BasicConstraints(extension));
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
