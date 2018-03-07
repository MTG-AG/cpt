
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;

public class IntegerValidator extends ValueValidator
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {
        RegExpValidator regexpValidator = new RegExpValidator("-?\\d+");
        return regexpValidator.validate(xmlValue);
    }
}
