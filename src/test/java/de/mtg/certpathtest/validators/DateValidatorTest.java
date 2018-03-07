
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.DateValidator}.
 *
 * @see de.mtg.certpathtest.validators.DateValidator DateValidator
 *
 *
 */
public class DateValidatorTest
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
        validator = new DateValidator();
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
        String testValue = "+1D";
        NotAfter test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(validator.validate(test));

        testValue = "-1D";
        test = new NotAfter(testValue, "UTC");
        Assert.assertTrue(validator.validate(test));

        testValue = "+700Y";
        test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(validator.validate(test));

        testValue = "-7M";
        test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(validator.validate(test));

        testValue = "-23H";
        test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(validator.validate(test));

        testValue = "J700D";
        test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(!validator.validate(test));

        testValue = "20170101";
        test = new NotAfter(testValue, "GEN");
        Assert.assertTrue(!validator.validate(test));

        testValue = "-1D";
        test = new NotAfter(testValue, "WRONG");
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
