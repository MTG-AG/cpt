/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.common;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Utilities for extensions.
 */
public class ExtUtil
{
    private ExtUtil()
    {
        // utilities
    }

    /**
     * Collects the elements of a sequence of extensions.
     *
     * @param extensions
     * @return list of extensions
     */
    public static List<SimpleExtension> collectExtensions(ASN1Sequence extensions)
    {
        List<SimpleExtension> extensionList = null;

        if (extensions != null)
        {
            extensionList = new ArrayList<SimpleExtension>(extensions.size());
            Enumeration<?> enu = extensions.getObjects();

            while (enu.hasMoreElements())
            {
                extensionList.add(SimpleExtension.getInstance(enu.nextElement()));
            }
        }

        return extensionList;
    }

    /**
     * Concatenates the given extensions.
     *
     * @param extensions
     * @return sequence of extensions
     */
    public static ASN1Sequence concatenateExtensions(List<SimpleExtension> extensions)
    {
        ASN1Sequence seq = null;

        if (extensions != null)
        {
            ASN1EncodableVector extVector = new ASN1EncodableVector();

            for (SimpleExtension extension : extensions)
            {
                extVector.add(extension);
            }
            seq = new DERSequence(extVector);
        }

        return seq;
    }

}
