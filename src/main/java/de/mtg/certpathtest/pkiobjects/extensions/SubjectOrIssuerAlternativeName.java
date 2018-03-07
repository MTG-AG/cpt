
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ByteArray;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesValidator;

/**
 *
 * Instances of this class represent the SubjectAlternativeName or IssuerAlternativeName extension. These two extension
 * have the same type of value and therefore it is not necessary to distinguish between them.
 *
 */
public class SubjectOrIssuerAlternativeName extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(SubjectOrIssuerAlternativeName.class);

    /**
     *
     * Constructs a SubjectAlternativeName or IssuerAlternativeName extension from its XML representation specified in
     * this xmlExtension. This representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public SubjectOrIssuerAlternativeName(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        GeneralName[] generalNameArray = new GeneralName[tokenizer.countTokens()];

        int counter = 0;
        while (tokenizer.hasMoreTokens())
        {

            GeneralName gn = null;
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, "=");

            String sanType = valueTokenizer.nextToken().trim();
            String sanValue = valueTokenizer.nextToken().trim();

            if ("rfc822Name".equalsIgnoreCase(sanType))
            {
                DERIA5String rfc822Name = new DERIA5String(sanValue);
                gn = new GeneralName(GeneralName.rfc822Name, rfc822Name);
            }
            else if ("dNSName".equalsIgnoreCase(sanType))
            {
                if (sanValue.indexOf("\0") != -1)
                {
                    logger.info("Found Null-Prefix value in DNS.");
                }

                byte[] rawSan = sanValue.getBytes();

                String prettyRawSan = ByteArray.prettyPrint(rawSan);

                if (prettyRawSan.indexOf(" 5C 30 ") != -1)
                {
                    logger.info("Found Null-Prefix value in DNS.");
                    prettyRawSan = prettyRawSan.replaceAll(Pattern.quote(" 5C 30 "), " 00 ");
                    DERIA5String dNSName = new DERIA5String(new String(new ByteArray(prettyRawSan, " ").getValue()));
                    gn = new GeneralName(GeneralName.dNSName, dNSName);
                }
                else
                {
                    DERIA5String dNSName = new DERIA5String(sanValue);
                    gn = new GeneralName(GeneralName.dNSName, dNSName);
                }

            }
            else if ("directoryName".equalsIgnoreCase(sanType))
            {
                X500Name directoryName = new X500Name(sanValue);
                gn = new GeneralName(GeneralName.directoryName, directoryName);
            }
            else if ("uniformResourceIdentifier".equalsIgnoreCase(sanType))
            {
                DERIA5String uri = new DERIA5String(sanValue);
                gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
            }
            else if ("iPAddress".equalsIgnoreCase(sanType))
            {
                gn = new GeneralName(GeneralName.iPAddress, sanValue);
            }
            else if ("registeredID".equalsIgnoreCase(sanType))
            {
                ASN1ObjectIdentifier registeredID = new ASN1ObjectIdentifier(sanValue);
                gn = new GeneralName(GeneralName.registeredID, registeredID);
            }

            generalNameArray[counter] = gn;
            counter += 1;

        }

        GeneralNames generalNames = new GeneralNames(generalNameArray);

        return generalNames.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>rfc822Name=a@a.de,dNSName=b.de,iPAddress=127.0.0.1</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Subject or Issuer Alternative Name extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        value = value.trim();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        while (tokenizer.hasMoreTokens())
        {
            String token = tokenizer.nextToken();

            token = token.trim();

            StringTokenizer valueTokenizer = new StringTokenizer(token, "=");

            String message = "Wrong value '" + value + "' for the Subject or Issuer Alternative Name extension.";

            if (valueTokenizer.countTokens() != 2)
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

            String sanType = valueTokenizer.nextToken();

            ConcreteValuesValidator concreteValuesValidator = new ConcreteValuesValidator(
                                                                                          "rfc822Name",
                                                                                              "dNSName",
                                                                                              "directoryName",
                                                                                              "uniformResourceIdentifier",
                                                                                              "iPAddress",
                                                                                              "registeredID");

            if (!concreteValuesValidator.validate(sanType))
            {
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }

        }

    }

}
