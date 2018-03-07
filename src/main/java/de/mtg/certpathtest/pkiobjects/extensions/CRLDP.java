
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;

/**
 *
 * Instances of this class represent the CRLDistributionPoints or FreshestCRL extension. These two extension have the
 * same type of value and therefore it is not necessary to distinguish between them.
 *
 */
public class CRLDP extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(CRLDP.class);

    /**
     *
     * Constructs a CRLDistributionPoints or FreshestCRL extension from its XML representation specified in this
     * xmlExtension. This representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public CRLDP(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException, IOException
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

        StringTokenizer tokenizer = new StringTokenizer(value, "|");

        int numbersOfDPS = tokenizer.countTokens();

        GeneralName[] generalNameArray = new GeneralName[numbersOfDPS];

        int i = 0;
        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken().trim();
            DERIA5String url = new DERIA5String(token);
            generalNameArray[i] = new GeneralName(6, url);
            i += 1;
        }

        GeneralNames generalNames = new GeneralNames(generalNameArray);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint[] distributionPoints = new DistributionPoint[1];
        distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
        CRLDistPoint crlDistributionPoint = new CRLDistPoint(distributionPoints);
        byte[] rawValue = crlDistributionPoint.getEncoded();
        return rawValue;
    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>http://crl.url.de|ldap://ldap.url.de/cn=DE?certificateRevocationList</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the CRL Distribution Points or Freshest CRL extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }
        return;

    }

}
