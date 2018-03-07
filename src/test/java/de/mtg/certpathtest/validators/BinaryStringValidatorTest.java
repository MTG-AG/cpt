
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.ValueValidator;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.BinaryStringValidator}.
 *
 * @see de.mtg.certpathtest.validators.BinaryStringValidator BinaryStringValidator
 *
 *
 */
public class BinaryStringValidatorTest
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
        validator = new BinaryStringValidator();
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
        validator = new BinaryStringValidator();

        String test = "10010010010010000100011100";
        Assert.assertTrue(validator.validate(test));

        test = "0000";
        Assert.assertTrue(validator.validate(test));

        test = "1111111111";
        Assert.assertTrue(validator.validate(test));

        test = "";
        Assert.assertTrue(!validator.validate(test));

        test = "11 000 00 00 00";
        Assert.assertTrue(!validator.validate(test));

        test = "12345678";
        Assert.assertTrue(!validator.validate(test));

        test = "ABCDEFGHIJKLMNOP";
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
