
package de.mtg.certpathtest.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.certpathtest.pkiobjects.Extension;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer}.
 *
 * @see de.mtg.certpathtest.pkiobjects.extensions.CertificateIssuer CertificateIssuer
 */
public class CertificateIssuerTest
{

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
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId());
        extension.setType("pretty");
        extension.setValue("CN=Test, C=DE|UTF8");

        CertificateIssuer certifiacteIssuer = new CertificateIssuer(extension);
        byte[] encoded = certifiacteIssuer.getEncoded();

        try(ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais))
        {
            DLSequence sequence = (DLSequence) asn1InputStream.readObject();
            DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);

            Assertions.assertEquals(GeneralName.directoryName, taggedObject.getTagNo());

            DERSequence dnSequence = (DERSequence) taggedObject.getObject();

            Assertions.assertEquals(2, dnSequence.size());

            DERSet cn = (DERSet) dnSequence.getObjectAt(0);
            DERSet c = (DERSet) dnSequence.getObjectAt(1);
            DERSequence cnSeq = (DERSequence) cn.getObjectAt(0);
            DERSequence cSeq = (DERSequence) c.getObjectAt(0);

            Assertions.assertEquals(2, cnSeq.size());
            Assertions.assertEquals(2, cSeq.size());
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

        Extension extension = new Extension();
        extension.setCritical("true");
        extension.setOid(org.bouncycastle.asn1.x509.Extension.certificateIssuer.getId());
        extension.setType("pretty");
        extension.setValue("CN=Test");

        Assertions.assertThrows(WrongPKIObjectException.class, () -> new CertificateIssuer(extension));

    }

}
