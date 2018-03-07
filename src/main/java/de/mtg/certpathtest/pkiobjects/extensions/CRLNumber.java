
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.IntegerValidator;

/**
 *
 * Instances of this class represent the CRLNumber extension.
 *
 */
public class CRLNumber extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(CRLNumber.class);

    /**
     *
     * Constructs a CRLNumber extension from its XML representation specified in this xmlExtension. This representation
     * is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public CRLNumber(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException, IOException
    {
        super(xmlExtension);

        validate();

    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws NoSuchAlgorithmException, IOException
    {

        String value = getValue();

        BigInteger crlNumber = new BigInteger(value);

        org.bouncycastle.asn1.x509.CRLNumber crlNumberExtension = new org.bouncycastle.asn1.x509.CRLNumber(crlNumber);

        return crlNumberExtension.getEncoded();
    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>1267</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {
        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the CRL Number extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        IntegerValidator integerValidator = new IntegerValidator();

        if (!integerValidator.validate(value))
        {
            String message = "This value '" + value + "' of the CRL Number extension is wrong.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
