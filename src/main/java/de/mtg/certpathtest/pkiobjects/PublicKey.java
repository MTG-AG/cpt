
package de.mtg.certpathtest.pkiobjects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlValue;

@XmlAccessorType(XmlAccessType.FIELD)
public class PublicKey
{

    @XmlAttribute
    private String type;
    @XmlValue
    private String value;

    public PublicKey()
    {

    }

    public PublicKey(String value, String type)
    {
        super();
        this.value = value;
        this.type = type;
    }

    public String getValue()
    {
        return value;
    }

    public void setValue(String value)
    {
        this.value = value;
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        this.type = type;
    }

}
