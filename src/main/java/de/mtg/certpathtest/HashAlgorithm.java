
package de.mtg.certpathtest;

import java.security.MessageDigest;

/**
 *
 * Enumeration for addressing hash algorithms.
 *
 */
public enum HashAlgorithm
{

    /**
     * Specifying the SHA1 hash algorithm.
     */
    SHA1("SHA1"),
    /**
     * Specifying the SHA224 hash algorithm.
     */
    SHA224("SHA224"),
    /**
     * Specifying the SHA256 hash algorithm.
     */
    SHA256("SHA256"),
    /**
     * Specifying the SHA384 hash algorithm.
     */
    SHA384("SHA384"),
    /**
     * Specifying the SHA512 hash algorithm.
     */
    SHA512("SHA512");

    /**
     * DER encoding of SHA1 OID. This can be used for preparing the PKCS1 signature format.
     */
    public static final ByteArray DIGEST_INFO_SHA1 = new ByteArray("30:21:30:09:06:05:2B:0E:03:02:1A:05:00:04:14", ":");

    /**
     * DER encoding of SHA224 OID. This can be used for preparing the PKCS1 signature format.
     */
    public static final ByteArray DIGEST_INFO_SHA224 =
        new ByteArray("30:2D:30:0D:06:09:60:86:48:01:65:03:04:02:04:05:00:04:1C", ":");

    /**
     * DER encoding of SHA256 OID. This can be used for preparing the PKCS1 signature format.
     */
    public static final ByteArray DIGEST_INFO_SHA256 =
        new ByteArray("30:31:30:0D:06:09:60:86:48:01:65:03:04:02:01:05:00:04:20", ":");

    /**
     * DER encoding of SHA384 OID. This can be used for preparing the PKCS1 signature format.
     */
    public static final ByteArray DIGEST_INFO_SHA384 =
        new ByteArray("30:41:30:0D:06:09:60:86:48:01:65:03:04:02:02:05:00:04:30", ":");

    /**
     * DER encoding of SHA512 OID. This can be used for preparing the PKCS1 signature format.
     */
    public static final ByteArray DIGEST_INFO_SHA512 =
        new ByteArray("30:51:30:0D:06:09:60:86:48:01:65:03:04:02:03:05:00:04:40", ":");

    private String name;

    HashAlgorithm(String name)
    {
        this.name = name;
    }

    /**
     *
     * Returns the DER encoded value of the OID of this hash algorithm. This can be used for preparing the PKCS1
     * signature format.
     *
     * @return the DER encoded value of the OID of this hash algorithm.
     */
    public byte[] getDigestInfo()
    {

        if (this.equals(SHA1))
        {
            return DIGEST_INFO_SHA1.getValue();
        }
        else if (this.equals(SHA224))
        {
            return DIGEST_INFO_SHA224.getValue();
        }
        else if (this.equals(SHA256))
        {
            return DIGEST_INFO_SHA256.getValue();
        }
        else if (this.equals(SHA384))
        {
            return DIGEST_INFO_SHA384.getValue();
        }
        else if (this.equals(SHA512))
        {
            return DIGEST_INFO_SHA512.getValue();
        }
        else
        {
            return null;
        }
    }

    /**
     *
     * Returns the name of this hash algorithm as this is usually is know to typical cryptographic providers. Therefore
     * it can be used when {@link MessageDigest} objects are instantiated.
     *
     * @return the name of this hash algorithm as this is usually is know to typical cryptographic providers.
     */
    public String getName()
    {
        return name;
    }

}
