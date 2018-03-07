
package de.mtg.certpathtest;

import java.nio.ByteBuffer;
import java.util.StringTokenizer;

/**
 *
 * Provides help methods often needed when working with byte arrays that are used for smart card communication. This
 * implementation is immutable.
 *
 */
public class ByteArray
{

    // the primitive type inner value of the byte array. On this all operations are performed.
    private byte[] rawValue;

    /**
     *
     * Constructs a newly allocated ByteArray object.
     *
     * @param value the primitive type
     */
    public ByteArray(byte[] value)
    {
        this.rawValue = new byte[value.length];
        System.arraycopy(value, 0, this.rawValue, 0, value.length);
    }

    /**
     *
     * Constructs a newly allocated ByteArray object from a human-friendly representation of a byte array. For example
     * "43:03:02" with delimiter ":" corresponds to the value 0x43 0x03 0x02. If the delimiter is empty then this value
     * is provided without any delimiter to be processed properly.
     *
     * @param value the byte array represented in hexadecimal form.
     * @param delimiter the delimiter symbol to distinguish each byte of this value.
     */
    public ByteArray(String value, String delimiter)
    {

        if (delimiter.isEmpty())
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < value.length(); i = i + 2)
            {
                sb.append(value.substring(i, i + 2));
                sb.append(":");
            }
            if (sb.length() > 0)
            {
                sb = sb.delete(sb.length() - 1, sb.length());
            }
            value = sb.toString();
            delimiter = ":";
        }

        StringTokenizer tokenizer = new StringTokenizer(value, delimiter);
        byte[] result = new byte[tokenizer.countTokens()];
        this.rawValue = new byte[tokenizer.countTokens()];
        int i = 0;
        while (tokenizer.hasMoreElements())
        {
            String byteAsString = tokenizer.nextToken();
            result[i] = (byte) (Integer.parseInt(byteAsString, 16) & 0xFF);
            i += 1;
        }
        System.arraycopy(result, 0, this.rawValue, 0, result.length);

    }

    /**
     *
     * Constructs a newly allocated ByteArray object from a human-friendly representation of a byte by repeating this
     * byte so many times as specified by this repeat. For example "FF" with repeat "4" corresponds to the value 0xFF
     * 0xFF 0xFF 0xFF.
     *
     * @param value the one byte represented in hexadecimal form to be repeated.
     * @param repeat the number of times this value should be repeated.
     */
    public ByteArray(String value, int repeat)
    {
        this.rawValue = new byte[repeat];
        byte[] result = new byte[1];
        result[0] = (byte) (Integer.parseInt(value, 16) & 0xFF);
        for (int i = 0; i < repeat; i++)
        {
            System.arraycopy(result, 0, this.rawValue, i, 1);
        }
    }

    /**
     *
     * Constructs a newly allocated ByteArray object from an integer. This is used especially to represent the length of
     * a byte array in a form that can be used in an APDU.
     *
     * Examples are.<br>
     * Input 1, Output 01 <br>
     * Input 127, Output 7F <br>
     * Input 128, Output 80 <br>
     * Input 255, Output FF <br>
     * Input 256, Output 0100 <br>
     * Input 863, Output 035F <br>
     * Input 1200, Output 04B0 <br>
     * Input 12000, Output 2EE0
     *
     * @param value a positive integer.
     * @throws IllegalArgumentException if the specified value is not greater than zero.
     */
    public ByteArray(int value)
    {
        if (value < 1)
        {
            throw new IllegalArgumentException("Invalid length for value. It must be greater than 0.");
        }

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(value);
        byte[] result = removeLeadingZeroBytes(bb.array());
        this.rawValue = new byte[result.length];
        System.arraycopy(result, 0, this.rawValue, 0, result.length);
    }


    /**
     *
     * Returns a new byte array free of any leading bytes that are zero. For example calling this method on "003456"
     * returns "3456", while calling this method on "00023456" returns "023456". This method is useful to eliminate the
     * padded zero bytes of a signed representation of big integers used in Java.
     *
     * @return this byte array free of any zero bytes at the beginning.
     */
    public byte[] removeLeadingZerosBytes()
    {
        return removeLeadingZeroBytes(this.rawValue);
    }

    /**
     *
     * Returns a new byte array free of any leading bytes that are zero. For example calling this method on "003456"
     * returns "3456", while calling this method on "00023456" returns "023456". This method is useful to eliminate the
     * padded zero bytes of a signed representation of big integers used in Java.
     *
     * @param ba the byte array to remove the leading zeros from.
     * @return this byte array free of any zero bytes at the beginning.
     */
    public static byte[] removeLeadingZeroBytes(byte[] ba)
    {
        int counter = 0;
        for (byte value : ba)
        {
            if (value == 0)
            {
                counter++;
            }
            else
            {
                break;
            }
        }

        byte[] value = new byte[ba.length - counter];
        System.arraycopy(ba, counter, value, 0, ba.length - counter);
        return value;
    }

    /**
     *
     * Puts the bytes specified by this value at the end of this array.
     *
     * @param value the byte array to append to this array.
     * @return a longer array with the bytes of this value placed at the end of this array.
     */
    public ByteArray append(byte[] value)
    {
        ByteBuffer bb = ByteBuffer.allocate(this.rawValue.length + value.length);
        bb.put(rawValue, 0, rawValue.length);
        bb.put(value, 0, value.length);
        return new ByteArray(bb.array());
    }

    /**
     *
     * Puts the bytes specified by this value at the start of this array.
     *
     * @param value the byte array to prepend to this array.
     * @return a longer array with the bytes of this value placed at the start of this array.
     */
    public ByteArray prepend(byte[] value)
    {
        ByteBuffer bb = ByteBuffer.allocate(this.rawValue.length + value.length);
        bb.put(value, 0, value.length);
        bb.put(rawValue, 0, rawValue.length);
        return new ByteArray(bb.array());
    }

    /**
     *
     * Puts the byte specified by this value at the end of this array.
     *
     * @param value the byte to append to this array.
     * @return a longer array with the byte of this value placed at the end of this array.
     */
    public ByteArray append(byte value)
    {
        ByteBuffer bb = ByteBuffer.allocate(this.rawValue.length + 1);
        bb.put(rawValue, 0, rawValue.length);
        bb.put(value);
        return new ByteArray(bb.array());
    }

    /**
     *
     * Puts the byte specified by this value at the start of this array.
     *
     * @param value the byte to prepend to this array.
     * @return a longer array with the byte of this value placed at the start of this array.
     */
    public ByteArray prepend(byte value)
    {
        ByteBuffer bb = ByteBuffer.allocate(this.rawValue.length + 1);
        bb.put(value);
        bb.put(rawValue, 0, rawValue.length);
        return new ByteArray(bb.array());
    }

    /**
     *
     * Returns this array as a representation of the Java primitive type byte.
     *
     * @return this array as a representation of the Java primitive type byte.
     */
    public byte[] getValue()
    {
        return this.rawValue;
    }

    /**
     *
     * The number of bytes in this array.
     *
     * @return the number of bytes in this array.
     */
    public int getLength()
    {
        return this.rawValue.length;
    }

    /**
     *
     * Returns a human-readable hexadecimal representation of this array. Each byte is separated by space and all digits
     * are capital.
     *
     * @return a human-readable hexadecimal representation of this array.
     */
    public String prettyPrint()
    {
        return print(true, getValue());
    }

    /**
     *
     * Returns a human-readable hexadecimal representation of this value. Each byte is separated by space and all digits
     * are capital.
     *
     * @param value the array to format to a human readable hexadecimal representation.
     * @return a human-readable hexadecimal representation of this value.
     */
    public static String prettyPrint(byte[] value)
    {
        return print(true, value);
    }

    /**
     *
     * Returns a human-readable hexadecimal representation of this array. The bytes are not separated to each other.
     *
     * @return a human-readable hexadecimal representation of this value.
     */
    public String toString()
    {
        return print(false, getValue());
    }

    /**
     *
     * Returns a human-readable hexadecimal representation of this value. The bytes are not separated to each other.
     *
     * @param value the array to format to a human readable hexadecimal representation.
     * @return a human-readable hexadecimal representation of this value.
     */
    public static String toString(byte[] value)
    {
        return print(false, value);
    }

    /**
     *
     * Returns a human-readable hexadecimal representation of this value. The bytes are separated to each other by a
     * space if this isPretty flag is set.
     *
     * @param isPretty true if the bytes must be separated by a space.
     * @param value the array to format to a human readable representation.
     * @return a human-readable hexadecimal representation of this value.
     */
    private static String print(boolean isPretty, byte[] value)
    {
        StringBuilder output = new StringBuilder();
        for (byte b : value)
        {
            output.append(String.format("%02X", b));
            if (isPretty)
            {
                output.append(" ");
            }
        }
        return output.toString().trim();
    }

}
