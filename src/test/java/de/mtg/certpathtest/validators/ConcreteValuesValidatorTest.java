
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.ValueValidator;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.ConcreteValuesValidator}.
 *
 * @see de.mtg.certpathtest.validators.ConcreteValuesValidator ConcreteValuesValidator
 *
 *
 */
public class ConcreteValuesValidatorTest
{

    private ValueValidator validator;

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {
        validator = new ConcreteValuesValidator();
    }

    /**
     *
     * Tests the basic behaviour of the class under test.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test() throws Exception
    {

        validator = new ConcreteValuesValidator("TA", "TC");

        String test = "TA";
        Assert.assertTrue(validator.validate(test));

        test = "TC";
        Assert.assertTrue(validator.validate(test));

        test = "TA,TC";
        Assert.assertTrue(!validator.validate(test));



    }

    /**
     *
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @After
    public void tearDown() throws Exception
    {

    }

}
