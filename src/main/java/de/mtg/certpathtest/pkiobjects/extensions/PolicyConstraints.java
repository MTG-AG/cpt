
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.math.BigInteger;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesValidator;
import de.mtg.certpathtest.validators.IntegerValidator;

/**
 *
 * Instances of this class represent the PolicyConstraints extension.
 *
 */
public class PolicyConstraints extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(PolicyConstraints.class);

    /**
     *
     * Constructs a PolicyConstraints extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public PolicyConstraints(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        BigInteger explicitPolicy = null;
        BigInteger inhibitPolicyMapping = null;

        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, "=");

            String constraintType = valueTokenizer.nextToken().trim();
            String constraintValue = valueTokenizer.nextToken().trim();

            if ("requireExplicitPolicy".equalsIgnoreCase(constraintType))
            {
                explicitPolicy = new BigInteger(constraintValue);
            }
            else if ("inhibitPolicyMapping".equalsIgnoreCase(constraintType))
            {
                inhibitPolicyMapping = new BigInteger(constraintValue);
            }

        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (explicitPolicy != null)
        {
            v.add(new DERTaggedObject(false, 0, new ASN1Integer(explicitPolicy)));
        }
        if (inhibitPolicyMapping != null)
        {
            v.add(new DERTaggedObject(false, 1, new ASN1Integer(inhibitPolicyMapping)));
        }

        byte[] encoded = new DERSequence(v).getEncoded();

        return encoded;
    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>requireExplicitPolicy=0,inhibitPolicyMapping=4</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Policy Constraints extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        value = value.trim();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        String message = "Wrong value '" + value + "' for the  Policy Constraints extension.";

        int numberOfTokens = tokenizer.countTokens();

        if (!(numberOfTokens == 1 || numberOfTokens == 2))
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, "=");

            numberOfTokens = valueTokenizer.countTokens();

            if (numberOfTokens != 2)
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            String constraintType = valueTokenizer.nextToken();
            String constraintValue = valueTokenizer.nextToken();

            ConcreteValuesValidator concreteValuesValidator =
                new ConcreteValuesValidator("requireExplicitPolicy", "inhibitPolicyMapping");

            if (!concreteValuesValidator.validate(constraintType))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            IntegerValidator integerValidator = new IntegerValidator();

            if (!integerValidator.validate(constraintValue))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

        }

    }

}
