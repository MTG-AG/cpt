
package de.mtg.certpathtest.validators;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.mtg.certpathtest.Modification;
import de.mtg.certpathtest.ValueValidator;
import junit.framework.Assert;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.validators.ModificationValidator}.
 *
 * @see de.mtg.certpathtest.validators.ModificationValidator ModificationValidator
 *
 *
 */
public class ModificationValidatorTest
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
        validator = new ModificationValidator();
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

        for (Modification modification : Modification.values())
        {
            de.mtg.certpathtest.pkiobjects.Modification modificationElement = new de.mtg.certpathtest.pkiobjects.Modification();
            modificationElement.setId(modification.name());
            Assert.assertTrue(validator.validate(modificationElement));
        }

        de.mtg.certpathtest.pkiobjects.Modification modificationElement = new de.mtg.certpathtest.pkiobjects.Modification();
        modificationElement.setId("wrong value. it does not exist");
        Assert.assertTrue(!validator.validate(modificationElement));

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
