
package de.mtg.certpathtest.pkiobjects;

public enum ValueType
{

    RAW("raw"), PRETTY("pretty");

    private String type;

    private ValueType(String type)
    {
        this.type = type;
    }

}
