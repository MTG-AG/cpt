package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.DateValidator}.
 *
 * @see de.mtg.certpathtest.validators.DateValidator DateValidator
 */
public class DateValidatorTest
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
        validator = new DateValidator();
    }

    /**
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test()
    {
        String testValue = "+1D";
        NotAfter test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(validator.validate(test));

        testValue = "-1D";
        test = new NotAfter(testValue, "UTC");
        Assertions.assertTrue(validator.validate(test));

        testValue = "+700Y";
        test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(validator.validate(test));

        testValue = "-7M";
        test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(validator.validate(test));

        testValue = "-23H";
        test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(validator.validate(test));

        testValue = "J700D";
        test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(!validator.validate(test));

        testValue = "20170101";
        test = new NotAfter(testValue, "GEN");
        Assertions.assertTrue(!validator.validate(test));

        testValue = "-1D";
        test = new NotAfter(testValue, "WRONG");
        Assertions.assertTrue(!validator.validate(test));

    }

}
