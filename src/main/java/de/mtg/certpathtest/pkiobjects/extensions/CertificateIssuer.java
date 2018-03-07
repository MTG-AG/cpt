
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.SubjectDN;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.ConcreteValuesValidator;
import de.mtg.certpathtest.validators.DNValidator;

/**
 *
 * Instances of this class represent the CertificateIssuer extension.
 *
 */
public class CertificateIssuer extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(CertificateIssuer.class);

    /**
     *
     * Constructs a CertificateIssuer extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public CertificateIssuer(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
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

        StringTokenizer tokenizer = new StringTokenizer(value, "|");

        String dn = tokenizer.nextToken().trim();
        String encoding = tokenizer.nextToken().trim();

        X500Name name = null;

        if ("UTF8".equalsIgnoreCase(encoding))
        {
            name = new X500Name(dn);
        }
        else if ("PrintableString".equalsIgnoreCase(encoding))
        {
            name = Utils.getAsPrintableStringName(dn);
        }

        GeneralNames generalNames = new GeneralNames(new GeneralName(name));

        return generalNames.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>CN=Test,C=DE|UTF8</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Certificate Issuer extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        StringTokenizer tokenizer = new StringTokenizer(value, "|");

        String message = "Wrong value '" + value + "' for the Certificate Issuer extension.";

        if (tokenizer.countTokens() != 2)
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        String dn = tokenizer.nextToken().trim();
        String encoding = tokenizer.nextToken().trim();

        SubjectDN subjectDN = new SubjectDN(dn, encoding);

        DNValidator dnValidator = new DNValidator();

        if (!dnValidator.validate(subjectDN))
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        ConcreteValuesValidator concreteValuesValidator = new ConcreteValuesValidator("UTF8", "PrintableString");

        if (!concreteValuesValidator.validate(encoding))
        {
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
