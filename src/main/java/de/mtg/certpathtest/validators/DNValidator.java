
package de.mtg.certpathtest.validators;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.SubjectDN;

public class DNValidator extends ValueValidator
{
    private static Logger logger = LoggerFactory.getLogger(DNValidator.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        String value = null;
        String encoding = null;

        if (xmlValue instanceof IssuerDN)
        {
            IssuerDN issuerDN = (IssuerDN) xmlValue;
            value = issuerDN.getValue();
            encoding = issuerDN.getEncoding();
        }
        else if (xmlValue instanceof SubjectDN)
        {
            SubjectDN subjectDN = (SubjectDN) xmlValue;
            value = subjectDN.getValue();
            encoding = subjectDN.getEncoding();
        }

        boolean correctValue = !value.isEmpty();

        try
        {
            new X500Name(value);
        }
        catch (Exception e)
        {
            logger.info("Inproper value " + value + " for DN.", e);
            return false;
        }

        boolean correctEncoding = false;

        if ("UTF8".equalsIgnoreCase(encoding))
        {
            correctEncoding = true;
        }
        else if ("PrintableString".equalsIgnoreCase(encoding))
        {
            correctEncoding = true;
        }

        return correctEncoding & correctValue;
    }
}
