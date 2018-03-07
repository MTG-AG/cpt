
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.RegExpValidator;

/**
 *
 * Instances of this class represent the BasicConstraints extension.
 *
 */
public class BasicConstraints extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(BasicConstraints.class);

    /**
     *
     * Constructs a BasicConstraints extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public BasicConstraints(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        String isCAString = tokenizer.nextToken().trim();

        String pathLengthConstraintsString = null;

        if (tokenizer.hasMoreTokens())
        {
            pathLengthConstraintsString = tokenizer.nextToken().trim();
        }

        ASN1Boolean isCA = ASN1Boolean.getInstance(Boolean.parseBoolean(isCAString));

        ASN1Integer pathLengthConstraints = null;

        if (pathLengthConstraintsString != null)
        {
            pathLengthConstraints = new ASN1Integer(Integer.parseInt(pathLengthConstraintsString));
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(isCA);

        if (pathLengthConstraints != null)
        {
            vector.add(pathLengthConstraints);
        }

        DERSequence seq = new DERSequence(vector);

        return seq.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>true,1</code>. The integer is optional.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Basic Constraints extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        RegExpValidator regexpValidator = new RegExpValidator("(true|false)(,\\s?-?\\d+)*");

        if (!regexpValidator.validate(value))
        {
            String message = "Wrong value '" + value + "' for the Basic Constraints extension.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
