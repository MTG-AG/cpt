
package de.mtg.certpathtest.validators;

import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.NextUpdate;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.RevocationDate;
import de.mtg.certpathtest.pkiobjects.ThisUpdate;

public class DateValidator extends ValueValidator
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        String value = null;
        String encoding = null;

        if (xmlValue instanceof NotBefore)
        {
            NotBefore notBefore = (NotBefore) xmlValue;
            value = notBefore.getValue();
            encoding = notBefore.getEncoding();
        }
        else if (xmlValue instanceof NotAfter)
        {
            NotAfter notAfter = (NotAfter) xmlValue;
            value = notAfter.getValue();
            encoding = notAfter.getEncoding();
        }
        else if (xmlValue instanceof ThisUpdate)
        {
            ThisUpdate thisUpdate = (ThisUpdate) xmlValue;
            value = thisUpdate.getValue();
            encoding = thisUpdate.getEncoding();
        }
        else if (xmlValue instanceof NextUpdate)
        {
            NextUpdate nextUpdate = (NextUpdate) xmlValue;
            value = nextUpdate.getValue();
            encoding = nextUpdate.getEncoding();
        }
        else if (xmlValue instanceof RevocationDate)
        {
            RevocationDate revocationDate = (RevocationDate) xmlValue;
            value = revocationDate.getValue();
            encoding = revocationDate.getEncoding();
        }

        RegExpValidator regexpValidator = new RegExpValidator("[\\+\\-]{1}\\d+[YMDH]{1}");
        boolean correctValue = regexpValidator.validate(value);

        boolean correctEncoding = false;

        if ("UTC".equalsIgnoreCase(encoding))
        {
            correctEncoding = true;
        }
        else if ("GEN".equalsIgnoreCase(encoding))
        {
            correctEncoding = true;
        }
        else if (encoding == null)
        {
            correctEncoding = true;
        }

        return correctEncoding & correctValue;
    }
}
