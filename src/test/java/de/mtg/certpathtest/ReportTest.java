
package de.mtg.certpathtest;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;

/**
 *
 * Used for testing the creation of a test report.
 *
 */
public class ReportTest
{

    /**
     *
     * Runs the program.
     *
     * @param args optional arguments.
     * @throws Exception if any error occurs.
     */
    public static void main(String[] args) throws Exception
    {

        List<String> test = new ArrayList<String>();

        test.add("CERT_PATH_COMMON_01");
        test.add("CERT_PATH_COMMON_02");
        test.add("CERT_PATH_EMAIL_02");
        test.add("CERT_PATH_EMAIL_01");
        test.add("CERT_PATH_EXT_11");
        test.add("CERT_PATH_TLS_SERVER_01");
        test.add("CERT_PATH_TLS_SERVER_02");
        test.add("CERT_PATH_TLS_SERVER_03");
        test.add("CERT_PATH_CRL_01");
        test.add("CERT_PATH_CRL_02");
        test.add("CERT_PATH_CRL_03");
        test.add("CERT_PATH_CRL_04");
        test.add("CERT_PATH_CRL_05");
        test.add("CERT_PATH_CRL_06");
        test.add("CERT_PATH_COMMON_09");
        test.add("CERT_PATH_COMMON_07");
        test.add("CERT_PATH_COMMON_08");
        test.add("CERT_PATH_COMMON_05");
        test.add("CERT_PATH_CRYPT_01");
        test.add("CERT_PATH_COMMON_06");
        test.add("CERT_PATH_COMMON_03");
        test.add("CERT_PATH_COMMON_04");
        test.add("CERT_PATH_CRYPT_02");
        test.add("CERT_PATH_CRL_10");
        test.add("CERT_PATH_CRL_11");
        test.add("CERT_PATH_CRL_12");
        test.add("CERT_PATH_CRL_13");
        test.add("CERT_PATH_CRL_14");
        test.add("CERT_PATH_COMMON_12");
        test.add("CERT_PATH_COMMON_13");
        test.add("CERT_PATH_COMMON_10");
        test.add("CERT_PATH_COMMON_11");
        test.add("CERT_PATH_ALGO_STRENGTH_03");
        test.add("CERT_PATH_ALGO_STRENGTH_02");
        test.add("CERT_PATH_ALGO_STRENGTH_01");
        test.add("CERT_PATH_TLS_CLIENT_01");
        test.add("CERT_PATH_TLS_CLIENT_02");
        test.add("CERT_PATH_EXT_01");
        test.add("CERT_PATH_EXT_02");
        test.add("CERT_PATH_IPSEC_01");
        test.add("CERT_PATH_IPSEC_02");
        test.add("CERT_PATH_IPSEC_03");
        test.add("CERT_PATH_EMAIL_04");
        test.add("CERT_PATH_EMAIL_05");
        test.add("CERT_PATH_EMAIL_03");
        test.add("CERT_PATH_EXT_12");
        test.add("CERT_PATH_EXT_13");
        test.add("CERT_PATH_EXT_10");
        test.add("CERT_PATH_CRL_07");
        test.add("CERT_PATH_CRL_08");
        test.add("CERT_PATH_CRL_09");
        test.add("CERT_PATH_EXT_05");
        test.add("CERT_PATH_EXT_06");
        test.add("CERT_PATH_EXT_03");
        test.add("CERT_PATH_EXT_04");
        test.add("CERT_PATH_EXT_09");
        test.add("CERT_PATH_EXT_07");
        test.add("CERT_PATH_EXT_08");
        test.add("CERT_PATH_EXT_16");
        test.add("CERT_PATH_EXT_17");
        test.add("CERT_PATH_EXT_14");
        test.add("CERT_PATH_EXT_15");
        test.add("CERT_PATH_EXT_18");
        test.add("CERT_PATH_EXT_19");
        test.add("CERT_PATH_TLS_CLIENT_05");
        test.add("CERT_PATH_TLS_CLIENT_06");
        test.add("CERT_PATH_TLS_CLIENT_03");
        test.add("CERT_PATH_TLS_CLIENT_04");
        test.add("CERT_PATH_IPSEC_04");
        test.add("CERT_PATH_IPSEC_05");
        test.add("CERT_PATH_IPSEC_06");
        test.add("CERT_PATH_IPSEC_07");

        Collections.sort(test);

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

        for (String testCaseId : test)
        {
            Row tippgeberCompanyRow = sheet.createRow((short) i);
            cell = tippgeberCompanyRow.createCell(0);
            cell.setCellValue(testCaseId);
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
        byte[] rawReport = outputBytes.toByteArray();

        Files.write(Paths.get("TestReport.xls"), rawReport);

    }

}
