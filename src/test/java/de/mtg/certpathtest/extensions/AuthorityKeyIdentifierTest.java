
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.AuthorityKeyIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.AuthorityKeyIdentifier}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.AuthorityKeyIdentifier AuthorityKeyIdentifier
 */
public class AuthorityKeyIdentifierTest
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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId());
        extension.setType("pretty");
        extension.setValue("");

        AuthorityKeyIdentifier akie = new AuthorityKeyIdentifier(extension, publicKey.getEncoded());
        byte[] encoded = akie.getEncoded();

        ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
        ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        DLSequence sequence = (DLSequence) asn1InputStream.readObject();
        DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);
        DEROctetString octetString = (DEROctetString) taggedObject.getObject();
        asn1InputStream.close();
        bais.close();

        Assertions.assertNotNull(octetString);
        Assertions.assertEquals(octetString.getOctets().length, 20);

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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId());
        extension.setType("pretty");
        extension.setValue("This should be empty");

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new AuthorityKeyIdentifier(extension, publicKey.getEncoded()));
    }

}
