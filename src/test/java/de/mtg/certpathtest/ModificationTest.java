
package de.mtg.certpathtest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * Unit tests for {@link de.mtg.certpathtest.Modification}.
 *
 * @see de.mtg.certpathtest.Modification Modification
 *
 *
 */
public class ModificationTest
{

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {

    }

    /**
     *
     * Tests the basic behaviour of the class under test.
     *
     */
    @Test(expected = IllegalArgumentException.class)
    public void test()
    {
        Modification.valueOf("a value that does not exist");
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
