
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.IntegerValidator}.
 *
 * @see de.mtg.certpathtest.validators.IntegerValidator IntegerValidator
 */
public class IntegerValidatorTest
{

    private ValueValidator validator;

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp()
    {
        validator = new IntegerValidator();
    }

    /**
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test()
    {

        String test = "10010010010010000100011100";
        Assertions.assertTrue(validator.validate(test));

        test = "0000";
        Assertions.assertTrue(validator.validate(test));

        test = "43874587234";
        Assertions.assertTrue(validator.validate(test));

        test = "4";
        Assertions.assertTrue(validator.validate(test));

        test = "";
        Assertions.assertTrue(!validator.validate(test));

        test = "123AB";
        Assertions.assertTrue(!validator.validate(test));

    }

}
