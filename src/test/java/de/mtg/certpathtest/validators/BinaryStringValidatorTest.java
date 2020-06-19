
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.BinaryStringValidator}.
 *
 * @see de.mtg.certpathtest.validators.BinaryStringValidator BinaryStringValidator
 */
public class BinaryStringValidatorTest
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
        validator = new BinaryStringValidator();
    }

    /**
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test() throws Exception
    {
        validator = new BinaryStringValidator();

        String test = "10010010010010000100011100";
        Assertions.assertTrue(validator.validate(test));

        test = "0000";
        Assertions.assertTrue(validator.validate(test));

        test = "1111111111";
        Assertions.assertTrue(validator.validate(test));

        test = "";
        Assertions.assertTrue(!validator.validate(test));

        test = "11 000 00 00 00";
        Assertions.assertTrue(!validator.validate(test));

        test = "12345678";
        Assertions.assertTrue(!validator.validate(test));

        test = "ABCDEFGHIJKLMNOP";
        Assertions.assertTrue(!validator.validate(test));
    }

}
