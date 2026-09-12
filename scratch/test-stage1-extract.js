/**
 * scratch/test-stage1-extract.js
 * 
 * Manual test script verifying extractTextFromFile() performance across
 * synthetic sample PDF, DOCX, XLSX, and TXT binary structures.
 */

const { extractTextFromFile } = require('../detectors/file-extract.js');

async function runManualExtractionTests() {
  console.log('===============================================================');
  console.log('       STAGE 1 MANUAL EXTRACTION TEST (PDF, DOCX, XLSX)        ');
  console.log('===============================================================\n');

  // 1. Sample PDF Binary Document
  const samplePdfContent = `
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 120 >>
stream
BT
/F1 12 Tf
(CONFIDENTIAL MEDICAL REPORT) Tj
(Patient John Doe SSN: 123-45-6789 diagnosed with Stage 2 Hypertension.) Tj
ET
endstream
endobj
xref
trailer
<< /Root 1 0 R >>
%%EOF
`;
  const pdfBytes = Buffer.from(samplePdfContent, 'utf-8');
  const pdfResult = await extractTextFromFile({ name: 'medical_report_confidential.pdf', buffer: pdfBytes, type: 'application/pdf' });

  console.log('--- TEST 1: PDF DOCUMENT ---');
  console.log('File Name:', pdfResult.fileName);
  console.log('Unscannable:', pdfResult.unscannable);
  console.log('Extracted Text:', JSON.stringify(pdfResult.text));
  console.log('Chunks Count:', pdfResult.chunks.length);
  console.log('---------------------------------------------------------------\n');

  // 2. Sample DOCX OpenXML Document
  const sampleDocxContent = `
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>PROJECT TITAN ACQUISITION MEMORANDUM</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Acme Corp purchasing target firm for $50M using master secret sk-live99887766554433221100.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
`;
  const docxBytes = Buffer.from(sampleDocxContent, 'utf-8');
  const docxResult = await extractTextFromFile({ name: 'acquisition_memo.docx', buffer: docxBytes, type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });

  console.log('--- TEST 2: DOCX WORD DOCUMENT ---');
  console.log('File Name:', docxResult.fileName);
  console.log('Unscannable:', docxResult.unscannable);
  console.log('Extracted Text:', JSON.stringify(docxResult.text));
  console.log('Chunks Count:', docxResult.chunks.length);
  console.log('---------------------------------------------------------------\n');

  // 3. Sample XLSX Spreadsheet Document
  const sampleXlsxContent = `
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="s"><v>EMPLOYEE PAYROLL LEDGER</v></c>
      <c r="B1" t="s"><v>Card: 4532-0150-0000-0007</v></c>
      <c r="C1" t="s"><v>Salary: $185,000</v></c>
    </row>
  </sheetData>
</worksheet>
`;
  const xlsxBytes = Buffer.from(sampleXlsxContent, 'utf-8');
  const xlsxResult = await extractTextFromFile({ name: 'payroll_ledger.xlsx', buffer: xlsxBytes, type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });

  console.log('--- TEST 3: XLSX SPREADSHEET ---');
  console.log('File Name:', xlsxResult.fileName);
  console.log('Unscannable:', xlsxResult.unscannable);
  console.log('Extracted Text:', JSON.stringify(xlsxResult.text));
  console.log('Chunks Count:', xlsxResult.chunks.length);
  console.log('---------------------------------------------------------------\n');

  // 4. Sample Image File (Fail-Closed Check)
  const imageResult = await extractTextFromFile({ name: 'scanned_medical_form.png', buffer: Buffer.from([137, 80, 78, 71]), type: 'image/png' });

  console.log('--- TEST 4: IMAGE FILE (FAIL-CLOSED GUARDRAIL) ---');
  console.log('File Name:', imageResult.fileName);
  console.log('Unscannable:', imageResult.unscannable);
  console.log('Reason:', imageResult.reason);
  console.log('---------------------------------------------------------------\n');
}

runManualExtractionTests();
