
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;

public class ModificationValidator extends ValueValidator
{
    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        de.mtg.certpathtest.pkiobjects.Modification value = (de.mtg.certpathtest.pkiobjects.Modification) xmlValue;

        try
        {
            de.mtg.certpathtest.Modification.valueOf(value.getId());
            return true;
        }
        catch (IllegalArgumentException iae)
        {
            return false;
        }
    }

}
