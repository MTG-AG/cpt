
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.PublicKeyValidator}.
 *
 * @see de.mtg.certpathtest.validators.PublicKeyValidator PublicKeyValidator
 *
 *
 */
public class PublicKeyValidatorTest
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
        validator = new PublicKeyValidator();
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
        String testValue = "RSA,2048";
        PublicKey test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "RSA, 2048";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "RSA, 512";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "RSA, 4096";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "ECDSA, 4096";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(!validator.validate(test));

        testValue = "ECDSA, prime192v1";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "ECDSA,prime256v1";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "ECDH, 4096";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(!validator.validate(test));

        testValue = "ECDH, prime192v1";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "ECDH,prime256v1";
        test = new PublicKey(testValue, "pretty");
        Assert.assertTrue(validator.validate(test));

        testValue = "AwIFoA==|AwIFoA==";
        test = new PublicKey(testValue, "raw");
        Assert.assertTrue(validator.validate(test));

        testValue = "AwIFoA==|AwIFoA==";
        test = new PublicKey(testValue, "type does not exist");
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
