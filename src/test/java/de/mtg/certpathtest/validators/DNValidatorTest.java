
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.DNValidator}.
 *
 * @see de.mtg.certpathtest.validators.DNValidator DNValidator
 *
 *
 */
public class DNValidatorTest
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
        validator = new DNValidator();
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
        String testValue = "CN=Test";
        IssuerDN test = new IssuerDN(testValue, "UTF8");
        Assert.assertTrue(validator.validate(test));

        testValue = "CN=Test, C=DE";
        test = new IssuerDN(testValue, "UTF8");
        Assert.assertTrue(validator.validate(test));

        testValue = "CN=Test, O=Test, C=DE";
        test = new IssuerDN(testValue, "UTF8");
        Assert.assertTrue(validator.validate(test));

        testValue = "O=Test, C=DE, CN=Test";
        test = new IssuerDN(testValue, "PrintableString");
        Assert.assertTrue(validator.validate(test));

        testValue = "CN=Test,O=Test,C=DE";
        test = new IssuerDN(testValue, "PrintableString");
        Assert.assertTrue(validator.validate(test));

        testValue = "CN=Test, O=Test, C=DE";
        test = new IssuerDN(testValue, "PrintableStringg");
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
