
package de.mtg.certpathtest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.bind.JAXBException;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import de.mtg.certpathtest.testcase.handlers.CreateCertificateHandler;
import de.mtg.certpathtest.testcase.handlers.EmailExportHandler;
import de.mtg.certpathtest.testcase.handlers.OutputHandler;
import de.mtg.certpathtest.testcase.handlers.PathExportHandler;
import de.mtg.tr03124.TestCase;

public class Runner
{

    private static Logger logger = LoggerFactory.getLogger(Runner.class);

    public Runner()
    {

    }

    public void run() throws IOException, JAXBException
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        ConcurrentHashMap<String, TestCase> testCases = objectCache.getTestCases();

        Enumeration<TestCase> testCaseEnumeration = testCases.elements();

        // insertion order is important, otherwise objects may reference other objects that have not been created.
        List<TestCase> insertionOrderTestCases = new ArrayList<>();
        List<String> insertionOrderTestCasesId = new ArrayList<>();

        while (testCaseEnumeration.hasMoreElements())
        {
            TestCase testCase = testCaseEnumeration.nextElement();

            if (!Utils.hasReference(testCase))
            {
                insertionOrderTestCases.add(testCase);
                insertionOrderTestCasesId.add(Utils.getTestCaseId(testCase));
            }
        }

        int previousSize = 0;

        List<String> wrongTestCases = null;

        while (insertionOrderTestCases.size() != testCases.size())
        {

            previousSize = insertionOrderTestCases.size();

            testCaseEnumeration = testCases.elements();

            wrongTestCases = new ArrayList<>();

            while (testCaseEnumeration.hasMoreElements())
            {

                TestCase testCase = testCaseEnumeration.nextElement();
                List<String> refids = Utils.getIdOfReferencedCertificates(testCase);

                boolean dependenciesResolved = true;

                for (String refid : refids)
                {
                    String testCaseId = objectCache.getTestCaseId(refid);

                    if (testCaseId == null)
                    {
                        Utils.exitProgramm("Test case with ID '" + testCase.getId()
                            + "' references a certificate that has not been created.");
                    }

                    // ignore references on the same test case, they have not been placed in the check list.
                    if (!testCaseId.equalsIgnoreCase(testCase.getId()))
                    {
                        if (!insertionOrderTestCasesId.contains(testCaseId))
                        {
                            dependenciesResolved = false;
                        }
                    }

                }

                if (dependenciesResolved)
                {
                    if (!insertionOrderTestCasesId.contains(Utils.getTestCaseId(testCase)))
                    {
                        insertionOrderTestCases.add(testCase);
                        insertionOrderTestCasesId.add(Utils.getTestCaseId(testCase));
                    }
                }
                else
                {
                    wrongTestCases.add(testCase.getId());
                }

            }

            // nothing was added in this step, a circle exists
            if (previousSize == insertionOrderTestCases.size())
            {
                Utils.exitProgramm("At least one test case references a certificate that has not been created. Wrong test case(s): "
                    + wrongTestCases + ".");
            }

        }

        // For each test case, issue certificates/CRLs and write them on the disc.
        for (TestCase testCase : insertionOrderTestCases)
        {

            String testCaseId = testCase.getId();

            MDC.put("TESTCASE", testCaseId);

            logger.info("Performing operations on test case '{}'.", testCaseId);
            CreateCertificateHandler certificateHandler = new CreateCertificateHandler(testCase);
            try
            {
                certificateHandler.execute();
            }
            catch (Exception e)
            {
                String errorMessage = "Error while performing operations on test case '" + testCaseId + "'";
                Utils.logError(errorMessage);
                logger.debug("", e);
                continue;
            }

            OutputHandler outputHandler = new OutputHandler(testCase);
            outputHandler.execute();

            PathExportHandler pathCreator = new PathExportHandler(testCase);
            pathCreator.execute();

            EmailExportHandler emailCreator = new EmailExportHandler(testCase);
            emailCreator.execute();

            logger.info("Successfully performed operations on test case '{}'.", testCaseId);
            MDC.remove("TESTCASE");
        }


        List<String> listToBeSorted = new ArrayList<String>();

        for (TestCase testCase : insertionOrderTestCases)
        {
            listToBeSorted.add(testCase.getId());
        }

        Collections.sort(listToBeSorted);

        byte[] xlsReport = createReport(listToBeSorted);

        String outputDirectoryName =
            ConfigurationProperties.getInstance().getProperties()
                                   .getString(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY);

        Files.write(Paths.get(outputDirectoryName, "report.xls"), xlsReport);

    }

    private byte[] createReport(List<String> testCaseList) throws IOException
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        Workbook wb = new HSSFWorkbook();
        Sheet sheet = wb.createSheet("Test Report");

        CellStyle boldStyle = wb.createCellStyle();
        Font font = wb.createFont();
        font.setBold(true);
        boldStyle.setFont(font);

        Row firstRow = sheet.createRow((short) 0);
        Cell cell = firstRow.createCell(0);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test Object Name:");

        Row secondRow = sheet.createRow((short) 1);
        cell = secondRow.createCell(0);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test Object Version:");

        sheet.createRow((short) 2);

        Row thirdRow = sheet.createRow((short) 3);
        cell = thirdRow.createCell(0);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test executed at:");

        Row forthRow = sheet.createRow((short) 4);
        cell = forthRow.createCell(0);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test executed by:");

        sheet.createRow((short) 5);
        Row testCasesTitleRow = sheet.createRow((short) 6);

        cell = testCasesTitleRow.createCell(0);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test Case ID");

        cell = testCasesTitleRow.createCell(1);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Expected Result");

        cell = testCasesTitleRow.createCell(2);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Test Result");

        cell = testCasesTitleRow.createCell(3);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Severity");

        cell = testCasesTitleRow.createCell(4);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Data");

        cell = testCasesTitleRow.createCell(5);
        cell.setCellStyle(boldStyle);
        cell.setCellValue("Remarks");

        int i = 7;

        for (String testCaseId : testCaseList)
        {
            Row tippgeberCompanyRow = sheet.createRow((short) i);
            cell = tippgeberCompanyRow.createCell(0);
            cell.setCellValue(testCaseId);

            TestCase testCase = objectCache.getTestCase(testCaseId);

            String expectedResult =
                Utils.getTestCaseExpectedResult(testCase) == null ? "n/a" : Utils.getTestCaseExpectedResult(testCase);

            String severity = Utils.getTestCaseSeverity(testCase) == null ? "n/a" : Utils.getTestCaseSeverity(testCase);

            List<String> certificateIds = objectCache.getCertificateIds(testCaseId);

            List<String> crlIds = objectCache.getCRLIds(testCaseId);

            StringBuilder testCaseObjects = new StringBuilder();

            for (String certificateId : certificateIds)
            {

                testCaseObjects.append(certificateId);
                testCaseObjects.append(", ");
            }

            for (String crlId : crlIds)
            {

                testCaseObjects.append(crlId);
                testCaseObjects.append(System.getProperty("line.separator"));
            }

            testCaseObjects.delete(testCaseObjects.length() - 2, testCaseObjects.length());

            cell = tippgeberCompanyRow.createCell(1);
            cell.setCellValue(expectedResult);
            cell = tippgeberCompanyRow.createCell(2);
            cell = tippgeberCompanyRow.createCell(3);
            cell.setCellValue(severity);
            cell = tippgeberCompanyRow.createCell(4);
            cell.setCellValue(testCaseObjects.toString());
            cell = tippgeberCompanyRow.createCell(5);

            i += 1;
        }

        sheet.autoSizeColumn(0);
        sheet.autoSizeColumn(1);
        sheet.autoSizeColumn(2);
        sheet.autoSizeColumn(3);
        sheet.autoSizeColumn(4);
        sheet.autoSizeColumn(5);

        ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        wb.write(outputBytes);
        outputBytes.flush();
        outputBytes.close();
        wb.close();
        return outputBytes.toByteArray();
    }

}