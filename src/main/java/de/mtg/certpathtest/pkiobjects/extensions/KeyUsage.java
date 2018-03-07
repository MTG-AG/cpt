
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesSetValidator;

/**
 *
 * Instances of this class represent the KeyUsage extension.
 *
 */
public class KeyUsage extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(KeyUsage.class);

    /**
     *
     * Constructs a KeyUsage extension from its XML representation specified in this xmlExtension. This representation
     * is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public KeyUsage(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException, IOException
    {
        super(xmlExtension);

        validate();

    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws NoSuchAlgorithmException, IOException
    {

        String value = getValue();
        StringTokenizer tokenizer = new StringTokenizer(value, ",");
        int keyUsageValue = 0;

        while (tokenizer.hasMoreElements())
        {
            String token = tokenizer.nextToken().trim();

            switch (token)
            {
                case "digitalSignature":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
                    break;
                case "nonRepudiation":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
                    break;
                case "keyEncipherment":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
                    break;
                case "dataEncipherment":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
                    break;
                case "keyAgreement":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
                    break;
                case "keyCertSign":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
                    break;
                case "cRLSign":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
                    break;
                case "encipherOnly":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.encipherOnly;
                    break;
                case "decipherOnly":
                    keyUsageValue = keyUsageValue | org.bouncycastle.asn1.x509.KeyUsage.decipherOnly;
                    break;
                default:
                    break;
            }

        }

        org.bouncycastle.asn1.x509.KeyUsage keyUsage = new org.bouncycastle.asn1.x509.KeyUsage(keyUsageValue);

        return keyUsage.getEncoded();
    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>digitalSignature,encipherOnly</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {
        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Key Usage extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        ConcreteValuesSetValidator concreteValuesValidator = new ConcreteValuesSetValidator(
                                                                                            "digitalSignature",
                                                                                                "nonRepudiation",
                                                                                                "keyEncipherment",
                                                                                                "dataEncipherment",
                                                                                                "keyAgreement",
                                                                                                "keyCertSign",
                                                                                                "cRLSign",
                                                                                                "encipherOnly",
                                                                                                "decipherOnly");
        if (!concreteValuesValidator.validate(value))
        {
            String message = "This value '" + value + "' of the Key Usage extension is wrong.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
