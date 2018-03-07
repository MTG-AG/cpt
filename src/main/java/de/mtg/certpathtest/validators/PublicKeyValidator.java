
package de.mtg.certpathtest.validators;

import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.ValueValidator;
import de.mtg.certpathtest.pkiobjects.PublicKey;

public class PublicKeyValidator extends ValueValidator
{
    private static Logger logger = LoggerFactory.getLogger(PublicKeyValidator.class);

    private static final String PRETTY_TYPE = "pretty";
    private static final String RAW_TYPE = "raw";

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        PublicKey testValue = (PublicKey) xmlValue;
        String value = testValue.getValue();
        String type = testValue.getType();

        if (value == null || type == null)
        {
            Utils.logError("value/type of public key not specified.");
            return false;
        }

        if (PRETTY_TYPE.equalsIgnoreCase(type))
        {

            boolean rsaMatches = false;
            boolean ecdsaMatches = false;
            boolean ecdhMatches = false;

            String pattern = "RSA,\\s?\\d+";
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(value);
            rsaMatches = m.matches();

            if (value.startsWith("ECDSA,"))
            {
                String curve = value.substring(6, value.length()).trim();
                ecdsaMatches = isKnownCurve(curve);
            }
            else if (value.startsWith("ECDH,"))
            {
                String curve = value.substring(5, value.length()).trim();
                ecdhMatches = isKnownCurve(curve);
            }

            return rsaMatches || ecdsaMatches || ecdhMatches;

        }
        else if (RAW_TYPE.equalsIgnoreCase(type))
        {
            try
            {

                value = value.trim();
                StringTokenizer tokenizer = new StringTokenizer(value, "|");

                String publicKeyString = tokenizer.nextToken();
                String privateKeyString = tokenizer.nextToken();

                Base64.decode(privateKeyString.trim());
                Base64.decode(publicKeyString.trim());

                return true;
            }
            catch (Exception e)
            {
                Utils.logError("Could not decode public key values. " + e);
                logger.debug("", e);
                return false;
            }
        }
        else
        {
            return false;
        }

    }

    private static boolean isKnownCurve(String curve)
    {
        ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec(curve);
        if (ecps == null)
        {
            return false;
        }
        return true;
    }

}
