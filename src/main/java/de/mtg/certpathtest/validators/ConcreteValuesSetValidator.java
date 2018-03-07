
package de.mtg.certpathtest.validators;

import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ValueValidator;

public class ConcreteValuesSetValidator extends ValueValidator
{
    private static Logger logger = LoggerFactory.getLogger(ConcreteValuesSetValidator.class);
    private String[] allowedValues;

    public ConcreteValuesSetValidator(String... allowedValues)
    {
        this.allowedValues = allowedValues;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        if (allowedValues == null)
        {
            return false;
        }

        String value = (String) xmlValue;

        ConcreteValuesValidator concreteValuesValidator = new ConcreteValuesValidator(allowedValues);

        // check for set of only one value
        if (value.indexOf(",") == -1)
        {
            if (!concreteValuesValidator.validate(value))
            {
                return false;
            }
        }

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        while (tokenizer.hasMoreElements())
        {
            String token = tokenizer.nextToken().trim();
            if (!concreteValuesValidator.validate(token))
            {
                return false;
            }
        }

        return true;

    }

}
