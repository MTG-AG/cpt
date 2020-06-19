
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.KeyUsage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.KeyUsage}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.KeyUsage KeyUsage
 */
public class KeyUsageTest
{

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {

        String correctValue = "digitalSignature, nonRepudiation";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.keyUsage.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);

        KeyUsage keyUsage = new KeyUsage(extension);
        byte[] encoded = keyUsage.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DERBitString bitString = (DERBitString) asn1InputStream.readObject();
            Assertions.assertEquals(bitString.intValue(), 192);
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

        String wrongValue = "digitalSignature, unknownKeyUsage";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.keyUsage.getId());
        extension.setType("pretty");
        extension.setValue(wrongValue);

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new KeyUsage(extension));

    }

    /**
     * Tests whether this extension cannot be created from a wrong representation and a proper exception is thrown.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testAgainstHighLevel() throws Exception
    {

        String correctValue =
                        "digitalSignature,nonRepudiation, keyEncipherment,dataEncipherment,keyAgreement,keyCertSign, cRLSign,encipherOnly,decipherOnly";

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.keyUsage.getId());
        extension.setType("pretty");
        extension.setValue(correctValue);
        KeyUsage keyUsage = new KeyUsage(extension);

        org.bouncycastle.asn1.x509.KeyUsage higheLevelKeyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                                        | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation
                                        | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
                                        | org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment
                                        | org.bouncycastle.asn1.x509.KeyUsage.keyAgreement
                                        | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                                        | org.bouncycastle.asn1.x509.KeyUsage.cRLSign
                                        | org.bouncycastle.asn1.x509.KeyUsage.encipherOnly
                                        | org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);
        // New case
        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

        correctValue = "digitalSignature";
        extension.setValue(correctValue);
        keyUsage = new KeyUsage(extension);
        higheLevelKeyUsage =
                        new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature);

        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

        // New case
        correctValue = "digitalSignature, nonRepudiation";
        extension.setValue(correctValue);
        keyUsage = new KeyUsage(extension);
        higheLevelKeyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                                        | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation);

        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

        // New case
        correctValue = "cRLSign, keyCertSign";
        extension.setValue(correctValue);
        keyUsage = new KeyUsage(extension);
        higheLevelKeyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                                        | org.bouncycastle.asn1.x509.KeyUsage.cRLSign);

        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

        // New case
        correctValue = "decipherOnly, keyCertSign";
        extension.setValue(correctValue);
        keyUsage = new KeyUsage(extension);
        higheLevelKeyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.decipherOnly
                                        | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign);

        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

        // New case
        correctValue = "decipherOnly, keyCertSign, nonRepudiation, cRLSign";
        extension.setValue(correctValue);
        keyUsage = new KeyUsage(extension);
        higheLevelKeyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.decipherOnly
                                        | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                                        | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation
                                        | org.bouncycastle.asn1.x509.KeyUsage.cRLSign);

        Assertions.assertTrue(Arrays.equals(keyUsage.getEncoded(), higheLevelKeyUsage.getEncoded()));

    }

}
