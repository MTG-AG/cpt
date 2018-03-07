
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesValidator;
import de.mtg.certpathtest.validators.RegExpValidator;

/**
 *
 * Instances of this class represent the InvalidityDate extension.
 *
 */
public class InvalidityDate extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(InvalidityDate.class);

    /**
     *
     * Constructs an InvalidityDate extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public InvalidityDate(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        String date = tokenizer.nextToken().trim();
        String encoding = tokenizer.nextToken().trim();

        Time time = null;

        if ("UTC".equalsIgnoreCase(encoding))
        {
            ASN1UTCTime utcTime = new ASN1UTCTime(Utils.convertValue(date));
            time = new Time(utcTime);
        }
        else if ("GEN".equalsIgnoreCase(encoding))
        {
            ASN1GeneralizedTime generalizedTime = new ASN1GeneralizedTime(Utils.convertValue(date));
            time = new Time(generalizedTime);
        }

        return time.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>-4H,GEN</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Invalidity Date extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        String message = "Wrong value '" + value + "' for the Invalidity Date extension.";

        if (tokenizer.countTokens() != 2)
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        String date = tokenizer.nextToken().trim();
        String encoding = tokenizer.nextToken();

        RegExpValidator regexpValidator = new RegExpValidator("[\\+\\-]{1}\\d+[YMDH]{1}");

        if (!regexpValidator.validate(date))
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        ConcreteValuesValidator concreteValuesValidator = new ConcreteValuesValidator("GEN", "UTC");

        if (!concreteValuesValidator.validate(encoding))
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
