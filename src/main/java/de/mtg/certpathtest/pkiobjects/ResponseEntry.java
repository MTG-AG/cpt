
package de.mtg.certpathtest.pkiobjects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.StringWriter;
import java.util.ArrayList;


@XmlRootElement
public class ResponseEntry
{

    private String refid;
    private String hashAlgorithm;
    private ThisUpdate thisUpdate;
    private NextUpdate nextUpdate;
    private CertStatus certStatus;

    private ArrayList<Extension> extensions = new ArrayList<>();

    public ResponseEntry()
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

    public String getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    @XmlElement(name = "HashAlgorithm")
    public void setHashAlgorithm(String hashAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
    }

    public CertStatus getCertStatus()
    {
        return certStatus;
    }

    @XmlElement(name = "CertStatus")
    public void setCertStatus(CertStatus certStatus)
    {
        this.certStatus = certStatus;
    }


    public ThisUpdate getThisUpdate()
    {
        return thisUpdate;
    }

    @XmlElement(name = "ThisUpdate")
    public void setThisUpdate(ThisUpdate thisUpdate)
    {
        this.thisUpdate = thisUpdate;
    }

    public NextUpdate getNextUpdate()
    {
        return nextUpdate;
    }

    @XmlElement(name = "NextUpdate")
    public void setNextUpdate(NextUpdate nextUpdate)
    {
        this.nextUpdate = nextUpdate;
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
            JAXBContext jaxbContext = JAXBContext.newInstance(ResponseEntry.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
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