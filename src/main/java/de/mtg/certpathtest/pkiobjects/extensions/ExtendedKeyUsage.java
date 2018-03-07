
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.RegExpValidator;

/**
 *
 * Instances of this class represent the ExtendedKeyUsage extension.
 *
 */
public class ExtendedKeyUsage extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(ExtendedKeyUsage.class);

    /**
     *
     * Constructs an ExtendedKeyUsage extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public ExtendedKeyUsage(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
                                                                                   IOException
    {
        super(xmlExtension);
        validate();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws IOException
    {
        String value = getValue();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        KeyPurposeId[] usages = new KeyPurposeId[tokenizer.countTokens()];

        int counter = 0;
        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken().trim();
            usages[counter] = KeyPurposeId.getInstance(new ASN1ObjectIdentifier(token));
            counter += 1;

        }

        org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage =
            new org.bouncycastle.asn1.x509.ExtendedKeyUsage(usages);
        return extendedKeyUsage.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>1.2.3.4.5,2.3.4.5</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Extended Key Usage extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        RegExpValidator regexpValidator = new RegExpValidator("((\\d+\\.{1})*\\d+){1}(,\\s?(\\d+\\.{1})*\\d+)*");

        if (!regexpValidator.validate(value))
        {
            String message = "Wrong value '" + value + "' for the Extended Key Usage extension.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
