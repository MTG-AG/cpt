
package de.mtg.certpathtest;

/**
 *
 * It is the base class for validators that check whether an XML element conforms to the specification. Implementations
 * of the methods of this class check the validity of different XML elements of the specification.
 *
 */
public abstract class ValueValidator
{

    /**
     *
     * Checks whether an XML element with this xmlValue has a correct value according to the specification. It can be
     * used to validate the value of an XML element before starting working with it.
     *
     * @param xmlValue the value of the XML Element that needs to be checked whether it is correct and can be further
     *            processed.
     * @return true if this xmlValue conforms to the specification, false otherwise.
     */
    public abstract boolean validate(Object xmlValue);
}
