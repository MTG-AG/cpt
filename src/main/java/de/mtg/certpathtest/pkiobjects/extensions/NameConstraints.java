
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesValidator;

/**
 *
 * Instances of this class represent the NameConstraints extension.
 *
 */
public class NameConstraints extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(NameConstraints.class);

    /**
     *
     * Constructs a NameConstraints extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public NameConstraints(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        GeneralSubtree[] permittedSubtrees = null;
        GeneralSubtree[] excludedSubtrees = null;

        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, ":");

            String nameConstraintsType = valueTokenizer.nextToken().trim();
            StringTokenizer nameConstraintsTokenizer = new StringTokenizer(valueTokenizer.nextToken(), "=");
            String sanType = nameConstraintsTokenizer.nextToken().trim();
            String sanValue = nameConstraintsTokenizer.nextToken().trim();

            if ("permitted".equalsIgnoreCase(nameConstraintsType))
            {
                permittedSubtrees = new GeneralSubtree[1];
                permittedSubtrees[0] = new GeneralSubtree(Utils.createGeneralName(sanType, sanValue));
            }
            else if ("excluded".equalsIgnoreCase(nameConstraintsType))
            {
                excludedSubtrees = new GeneralSubtree[1];
                excludedSubtrees[0] = new GeneralSubtree(Utils.createGeneralName(sanType, sanValue));

            }

        }

        org.bouncycastle.asn1.x509.NameConstraints nameConstraints =
            new org.bouncycastle.asn1.x509.NameConstraints(permittedSubtrees, excludedSubtrees);
        return nameConstraints.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>permitted:dNSName=a.de,excluded:rfc822name=b@b.de</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Name Constraints extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        value = value.trim();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, ":");

            int numberOfTokens = valueTokenizer.countTokens();

            String message = "Wrong value '" + value + "' for the  Name Constraints extension.";

            if (!(numberOfTokens == 1 || numberOfTokens == 2))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            String nameConstraintsType = valueTokenizer.nextToken();

            ConcreteValuesValidator concreteValuesValidator = new ConcreteValuesValidator("permitted", "excluded");

            if (!concreteValuesValidator.validate(nameConstraintsType))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            String nameConstraintValue = valueTokenizer.nextToken();

            StringTokenizer nameConstraintValueTokenizer = new StringTokenizer(nameConstraintValue, "=");

            if (nameConstraintValueTokenizer.countTokens() != 2)
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            String nameConstraintsValueType = nameConstraintValueTokenizer.nextToken();

            concreteValuesValidator = new ConcreteValuesValidator(
                                                                  "rfc822Name",
                                                                      "dNSName",
                                                                      "directoryName",
                                                                      "uniformResourceIdentifier",
                                                                      "iPAddress",
                                                                      "registeredID");

            if (!concreteValuesValidator.validate(nameConstraintsValueType))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

        }

    }

}
