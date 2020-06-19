
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.SubjectKeyIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.SubjectKeyIdentifier}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.SubjectKeyIdentifier SubjectKeyIdentifier
 */
public class SubjectKeyIdentifierTest
{

    private PublicKey publicKey;

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        publicKey = keyPair.getPublic();
    }

    /**
     * Tests whether this extension can be created correctly from a correct representation.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testCorrect() throws Exception
    {
        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
        extension.setType("pretty");
        extension.setValue("");

        SubjectKeyIdentifier skie = new SubjectKeyIdentifier(extension, publicKey.getEncoded());
        byte[] encoded = skie.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DEROctetString octetString = (DEROctetString) asn1InputStream.readObject();
            Assertions.assertNotNull(octetString);
            Assertions.assertEquals(octetString.getOctets().length, 20);
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

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
        extension.setType("pretty");
        extension.setValue("This should be empty");

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new SubjectKeyIdentifier(extension, publicKey.getEncoded()));

    }

}
