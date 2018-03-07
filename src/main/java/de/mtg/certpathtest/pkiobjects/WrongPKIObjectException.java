
package de.mtg.certpathtest.pkiobjects;

/**
 * Instances of this class express error in the XML structure of PKI objects.
 *
 */
public class WrongPKIObjectException extends Exception
{

    /**
     *
     * Constructs a newly allocated WrongPKIObjectException object.
     *
     */
    public WrongPKIObjectException()
    {
        super();
    }

    /**
     *
     * Constructs a newly allocated WrongPKIObjectException object.
     *
     * @param message the message associated with this exception.
     */
    public WrongPKIObjectException(String message)
    {
        super(message);
    }

    /**
     *
     * Constructs a newly allocated WrongPKIObjectException object.
     *
     * @param throwable the throwable.
     */
    public WrongPKIObjectException(Throwable throwable)
    {
        super(throwable);
    }

    /**
     *
     * Constructs a newly allocated WrongPKIObjectException object.
     *
     * @param message the message associated with this exception.
     * @param throwable the throwable.
     */
    public WrongPKIObjectException(String message, Throwable throwable)
    {
        super(message, throwable);
    }

}
