
package de.mtg.certpathtest.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.mtg.certpathtest.ValueValidator;

public class RegExpValidator extends ValueValidator
{

    private String pattern;

    /**
     *
     * Constructs a newly allocated RegExpValidator object.
     *
     * @param pattern the regular expression pattern for validate against it.
     */
    public RegExpValidator(String pattern)
    {
        this.pattern = pattern;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {
        String testValue = (String) xmlValue;
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(testValue);
        return m.matches();
    }
}
