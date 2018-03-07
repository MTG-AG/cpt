
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;

/**
 *
 * Instances of this class represent the SubjectInformationAccess extension.
 *
 */
public class SubjectInformationAccess extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(SubjectInformationAccess.class);

    /**
     *
     * Constructs a SubjectInformationAccess extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public SubjectInformationAccess(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
                                                                                           IOException
    {
        super(xmlExtension);
        validate();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws IOException
    {
        String value = getValue().trim();

        org.bouncycastle.asn1.x509.AuthorityInformationAccess aia =
            new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                                                                      new AccessDescription(
                                                                                            AccessDescription.id_ad_caIssuers,
                                                                                                new GeneralName(
                                                                                                                GeneralName.uniformResourceIdentifier,
                                                                                                                    value)));

        return aia.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: anything can be used.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Authority Information Access extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
