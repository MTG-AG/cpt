
package de.mtg.security.asn1.x509.common;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test of {@link SimpleExtension}.
 */
public class SimpleExtensionTest
{
    private static Logger logger = LoggerFactory.getLogger(SimpleExtensionTest.class);

    /**
     * Tests building an extension.
     *
     * @throws IOException if the extension cannot be encoded.
     */
    @Test
    public void buildExtension() throws IOException
    {
        ASN1ObjectIdentifier oid = Extension.basicConstraints;
        byte[] extnValueOctets = {0x30, 0};

        SimpleExtension extension = new SimpleExtension(oid);
        extension.setCritical(true);
        extension.setExtnValueOctets(extnValueOctets);

        // clone
        byte[] extBytes = extension.getEncoded(ASN1Encoding.DER);
        SimpleExtension newExtension = SimpleExtension.getInstance(extBytes);

        logger.debug("newExtension: {}", ASN1Dump.dumpAsString(newExtension, true));

        Assertions.assertEquals(oid, newExtension.getExtnId());
        Assertions.assertEquals(ASN1Boolean.TRUE, newExtension.getCritical());
        Assertions.assertArrayEquals(extnValueOctets, newExtension.getExtnValueOctets());
    }

}
