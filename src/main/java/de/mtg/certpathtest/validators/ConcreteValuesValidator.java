
package de.mtg.certpathtest.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ValueValidator;

public class ConcreteValuesValidator extends ValueValidator
{
    private static Logger logger = LoggerFactory.getLogger(ConcreteValuesValidator.class);
    private String[] allowedValues;

    private static final int HEX_RADIX = 16;

    public ConcreteValuesValidator(String... allowedValues)
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

        String value = ((String) xmlValue).trim();

        for (String allowedValue : allowedValues)
        {
            if (allowedValue.equalsIgnoreCase(value))
            {
                return true;
            }
        }

        return false;

    }

}
