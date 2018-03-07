
package de.mtg.certpathtest.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ValueValidator;

public class BinaryStringValidator extends ValueValidator
{
    private static Logger logger = LoggerFactory.getLogger(BinaryStringValidator.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {
        RegExpValidator regexpValidator = new RegExpValidator("[0-1]+");
        return regexpValidator.validate(xmlValue);
    }
}
