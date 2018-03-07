
package de.mtg.certpathtest.validators;

import java.security.PrivateKey;

import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.ValueValidator;

public class PrivateKeyValidator extends ValueValidator
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean validate(Object xmlValue)
    {

        String id = (String) xmlValue;
        id = id.trim();

        ObjectCache objectCache = ObjectCache.getInstance();

        PrivateKey privateKey = objectCache.getPrivateKey(id);

        if (objectCache.getPrivateKey(id) == null)
        {
            Utils.logError("Could not find key with id '" + id + "'.");
            return false;
        }

        if (!("EC".equalsIgnoreCase(privateKey.getAlgorithm()) || "RSA".equalsIgnoreCase(privateKey.getAlgorithm())
            || "ECDSA".equalsIgnoreCase(privateKey.getAlgorithm())))
        {
            Utils.logError("Found key for algorithm '" + privateKey.getAlgorithm()
                + "' that cannot be used for signing.");
            return false;
        }

        return true;

    }
}
