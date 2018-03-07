
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;

import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;

/**
 *
 * Instances of this class represent the IssuingDistributionPoint extension.
 *
 */
public class IssuingDistributionPoint extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(IssuingDistributionPoint.class);

    /**
     *
     * Constructs an IssuingDistributionPoint extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public IssuingDistributionPoint(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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
        String value = getValue();

        GeneralNames generalNames = new GeneralNames(new GeneralName(6, value.trim()));
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        org.bouncycastle.asn1.x509.IssuingDistributionPoint issuingDistributionPointNew =
            new org.bouncycastle.asn1.x509.IssuingDistributionPoint(
                                                                    distributionPointName,
                                                                        false,
                                                                        false,
                                                                        null,
                                                                        false,
                                                                        false);
        byte[] rawValue = issuingDistributionPointNew.getEncoded();
        return rawValue;
    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>http://crl.url.de</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Issuing Distribution Point extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }
        return;

    }

}
