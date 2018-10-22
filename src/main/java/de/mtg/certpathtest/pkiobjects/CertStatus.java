
package de.mtg.certpathtest.pkiobjects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.StringWriter;

@XmlRootElement
public class CertStatus
{

    private String status;
    private RevocationDate revocationDate;
    private String revocationReason;

    public CertStatus()
    {

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

    public String getRevocationReason()
    {
        return revocationReason;
    }

    @XmlElement(name = "RevocationReason")
    public void setRevocationReason(String revocationReason)
    {
        this.revocationReason = revocationReason;
    }

    public String getStatus()
    {
        return status;
    }

    @XmlElement(name = "Status")
    public void setStatus(String status)
    {
        this.status = status;
    }


    @Override
    public String toString()
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(CertStatus.class);
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