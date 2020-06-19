
package de.mtg.certpathtest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link de.mtg.certpathtest.Modification}.
 *
 * @see de.mtg.certpathtest.Modification Modification
 */
public class ModificationTest
{

    /**
     * Tests the basic behaviour of the class under test.
     */
    @Test
    public void test()
    {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Modification.valueOf("a value that does not exist"));
    }

}
