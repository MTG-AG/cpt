
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;

import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;

/**
 *
 * Instances of this class represent the SubjectDirectoryAttributes extension.
 *
 */
public class SubjectDirectoryAttributes extends XMLExtension
{

    /**
     *
     * Constructs a SubjectDirectoryAttributes extension from its XML representation specified in this xmlExtension.
     * This representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public SubjectDirectoryAttributes(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
                                                                                             IOException
    {
        super(xmlExtension);
        validate();
    }

    /**
     *
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException because this extension does not have a pretty representation.
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws IOException
    {
        throw new UnsupportedOperationException(
                                                "The Subject Directory Attributes extension does not have a pretty representation.");
    }

    /**
     *
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException because this extension does not have a pretty representation.
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {
        throw new UnsupportedOperationException(
                                                "The Subject Directory Attributes extension does not have a pretty representation.");

    }

}
