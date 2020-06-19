
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.DNValidator}.
 *
 * @see de.mtg.certpathtest.validators.DNValidator DNValidator
 */
public class DNValidatorTest
{

    private ValueValidator validator;

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp() throws Exception
    {
        validator = new DNValidator();
    }

    /**
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test()
    {
        String testValue = "CN=Test";
        IssuerDN test = new IssuerDN(testValue, "UTF8");
        Assertions.assertTrue(validator.validate(test));

        testValue = "CN=Test, C=DE";
        test = new IssuerDN(testValue, "UTF8");
        Assertions.assertTrue(validator.validate(test));

        testValue = "CN=Test, O=Test, C=DE";
        test = new IssuerDN(testValue, "UTF8");
        Assertions.assertTrue(validator.validate(test));

        testValue = "O=Test, C=DE, CN=Test";
        test = new IssuerDN(testValue, "PrintableString");
        Assertions.assertTrue(validator.validate(test));

        testValue = "CN=Test,O=Test,C=DE";
        test = new IssuerDN(testValue, "PrintableString");
        Assertions.assertTrue(validator.validate(test));

        testValue = "CN=Test, O=Test, C=DE";
        test = new IssuerDN(testValue, "PrintableStringg");
        Assertions.assertTrue(!validator.validate(test));
    }

}
