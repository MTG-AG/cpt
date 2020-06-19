
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.ConcreteValuesValidator}.
 *
 * @see de.mtg.certpathtest.validators.ConcreteValuesValidator ConcreteValuesValidator
 */
public class ConcreteValuesValidatorTest
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
        validator = new ConcreteValuesValidator();
    }

    /**
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test() throws Exception
    {

        validator = new ConcreteValuesValidator("TA", "TC");

        String test = "TA";
        Assertions.assertTrue(validator.validate(test));

        test = "TC";
        Assertions.assertTrue(validator.validate(test));

        test = "TA,TC";
        Assertions.assertTrue(!validator.validate(test));

    }

}
