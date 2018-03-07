
package de.mtg.certpathtest.pkiobjects;

import java.io.StringWriter;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class RevokedCertificate
{

    private String refid;
    private RevocationDate revocationDate;

    private ArrayList<Extension> extensions = new ArrayList<>();

    public RevokedCertificate()
    {

    }

    public String getRefid()
    {
        return refid;
    }

    @XmlAttribute
    public void setRefid(String refid)
    {
        this.refid = refid;
    }

    public RevocationDate getRevocationDate()
    {
        return revocationDate;
    }

    @XmlElement(name = "RevocationDate")
    public void setRevocationDate(RevocationDate revocationDate)
    {
        this.revocationDate = revocationDate;
    }

    public ArrayList<Extension> getExtensions()
    {
        return extensions;
    }

    @XmlElement(name = "Extension")
    public void setExtensions(ArrayList<Extension> extensions)
    {
        this.extensions = extensions;
    }

    @Override
    public String toString()
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(RevokedCertificate.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            StringWriter stringWriter = new StringWriter();
            marshaller.marshal(this, stringWriter);
            stringWriter.flush();
            stringWriter.close();
            return stringWriter.toString();
        }
        catch (Exception e)
        {
            return "";
        }

    }

}