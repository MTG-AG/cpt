
package de.mtg.certpathtest.pkiobjects;

import java.io.StringWriter;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class Certificate
{

    private String id;
    private String type;
    private String refid;
    private String overwrite;

    private String verifiedBy;
    private String version;
    private String serialNumber;
    private String signature;
    private IssuerDN issuerDN;
    private SubjectDN subjectDN;
    private NotBefore notBefore;
    private NotAfter notAfter;
    private PublicKey publicKey;
    private String issuerUniqueID;
    private String subjectUniqueID;
    private ArrayList<Extension> extensions = new ArrayList<>();
    private Modification modification;

    public Certificate()
    {

    }

    public String getId()
    {
        return id;
    }

    @XmlAttribute
    public void setId(String id)
    {
        this.id = id;
    }

    public String getType()
    {
        return type;
    }

    @XmlAttribute
    public void setType(String type)
    {
        this.type = type;
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

    public String getOverwrite()
    {
        return overwrite;
    }

    @XmlAttribute
    public void setOverwrite(String overwrite)
    {
        this.overwrite = overwrite;
    }

    public String getVerifiedBy()
    {
        return verifiedBy;
    }

    @XmlElement(name = "VerifiedBy")
    public void setVerifiedBy(String verifiedBy)
    {
        this.verifiedBy = verifiedBy;
    }

    public String getVersion()
    {
        return version;
    }

    @XmlElement(name = "Version")
    public void setVersion(String version)
    {
        this.version = version;
    }

    public String getSerialNumber()
    {
        return serialNumber;
    }

    @XmlElement(name = "SerialNumber")
    public void setSerialNumber(String serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public String getSignature()
    {
        return signature;
    }

    @XmlElement(name = "Signature")
    public void setSignature(String signature)
    {
        this.signature = signature;
    }

    public IssuerDN getIssuerDN()
    {
        return issuerDN;
    }

    @XmlElement(name = "IssuerDN")
    public void setIssuerDN(IssuerDN issuerDN)
    {
        this.issuerDN = issuerDN;
    }

    public SubjectDN getSubjectDN()
    {
        return subjectDN;
    }

    @XmlElement(name = "SubjectDN")
    public void setSubjectDN(SubjectDN subjectDN)
    {
        this.subjectDN = subjectDN;
    }

    public NotBefore getNotBefore()
    {
        return notBefore;
    }

    @XmlElement(name = "NotBefore")
    public void setNotBefore(NotBefore notBefore)
    {
        this.notBefore = notBefore;
    }

    public NotAfter getNotAfter()
    {
        return notAfter;
    }

    @XmlElement(name = "NotAfter")
    public void setNotAfter(NotAfter notAfter)
    {
        this.notAfter = notAfter;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    @XmlElement(name = "PublicKey")
    public void setPublicKey(PublicKey publicKey)
    {
        this.publicKey = publicKey;
    }

    public String getIssuerUniqueID()
    {
        return issuerUniqueID;
    }

    @XmlElement(name = "IssuerUniqueID")
    public void setIssuerUniqueID(String issuerUniqueID)
    {
        this.issuerUniqueID = issuerUniqueID;
    }

    public String getSubjectUniqueID()
    {
        return subjectUniqueID;
    }

    @XmlElement(name = "SubjectUniqueID")
    public void setSubjectUniqueID(String subjectUniqueID)
    {
        this.subjectUniqueID = subjectUniqueID;
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

    public Modification getModification()
    {
        return modification;
    }

    @XmlElement(name = "Modification")
    public void setModification(Modification modification)
    {
        this.modification = modification;
    }

    @Override
    public String toString()
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(Certificate.class);
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