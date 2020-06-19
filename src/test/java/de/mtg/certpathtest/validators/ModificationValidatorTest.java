
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.Modification;
import de.mtg.certpathtest.ValueValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.validators.ModificationValidator}.
 *
 * @see de.mtg.certpathtest.validators.ModificationValidator ModificationValidator
 */
public class ModificationValidatorTest
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
        validator = new ModificationValidator();
    }

    /**
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
            Assertions.assertTrue(validator.validate(modificationElement));
        }

        de.mtg.certpathtest.pkiobjects.Modification modificationElement = new de.mtg.certpathtest.pkiobjects.Modification();
        modificationElement.setId("wrong value. it does not exist");
        Assertions.assertFalse(validator.validate(modificationElement));

    }

}
