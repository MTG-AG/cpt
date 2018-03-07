
package de.mtg.certpathtest.testcase.handlers;

import de.mtg.tr03124.TestCase;

public abstract class TestCaseHandler
{

    public TestCaseHandler(TestCase testCase)
    {

    }

    public abstract void execute() throws Exception;
}
