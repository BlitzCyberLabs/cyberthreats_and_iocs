/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Native Word DOCX Generator
 * Uses the official 'docx' package to generate the Student Questionnaire and Instructor Answer Key.
 */

import { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, BorderStyle } from 'docx';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const publicDocsDir = path.join(__dirname, '..', '..', 'public', 'documents');
const rootDocsDir = path.join(__dirname, '..', '..');

if (!fs.existsSync(publicDocsDir)) {
  fs.mkdirSync(publicDocsDir, { recursive: true });
}

async function generateQuestionnaire() {
  const doc = new Document({
    sections: [{
      properties: {},
      children: [
        new Paragraph({
          text: "BLITZ CYBER THREATS & IOC INVESTIGATION LAB",
          heading: HeadingLevel.TITLE,
          spacing: { after: 120 }
        }),
        new Paragraph({
          text: "Official Student Lab Questionnaire & Field Assessment Report",
          heading: HeadingLevel.HEADING_2,
          spacing: { after: 240 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Student Name: ___________________________    ", bold: true }),
            new TextRun({ text: "Session ID: ___________________________", bold: true })
          ],
          spacing: { after: 120 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Connection Public IP: _____________________    ", bold: true }),
            new TextRun({ text: "Date / Time: ___________________________", bold: true })
          ],
          spacing: { after: 240 }
        }),

        new Paragraph({
          text: "1. Lab Instructions & Overview",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 200, after: 120 }
        }),
        new Paragraph({
          text: "Welcome to the BLITZ Cyber Threats & IOC Investigation Lab. You will perform three controlled offensive exercises in the Attack Lab, analyze the resulting telemetry in the enterprise SOC dashboard, identify Indicators of Compromise (IoCs), and record your retrieved flags below.",
          spacing: { after: 180 }
        }),

        // Challenge 1
        new Paragraph({
          text: "2. Challenge 1: SQL Injection Authentication Bypass",
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 200, after: 100 }
        }),
        new Paragraph({
          text: "Task Description: Navigate to the Attack Lab and access the vulnerable login portal (POST /api/challenge/sqli/login). Craft and inject a SQL boolean tautology or comment delimiter to bypass authentication and gain administrative privileges.",
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 1.1 (Attack Execution Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 1.2 (SOC Investigation Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Investigation Observations (HTTP method, status code, payload in request body):" }),
            new TextRun({ text: "\n_________________________________________________________________________________\n_________________________________________________________________________________" })
          ],
          spacing: { after: 180 }
        }),

        // Challenge 2
        new Paragraph({
          text: "3. Challenge 2: Cross-Site Scripting (Reflected XSS)",
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 200, after: 100 }
        }),
        new Paragraph({
          text: "Task Description: In the Attack Lab sandboxed frame, inject the required payload <script>alert('2')</script> into the search bar. Observe DOM script execution and the resulting browser alert.",
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 2.1 (Attack Execution Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 2.2 (SOC Investigation Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Investigation Observations (URL encoding in access URI, script tags observed):" }),
            new TextRun({ text: "\n_________________________________________________________________________________\n_________________________________________________________________________________" })
          ],
          spacing: { after: 180 }
        }),

        // Challenge 3
        new Paragraph({
          text: "4. Challenge 3: Insecure Direct Object Reference (IDOR)",
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 200, after: 100 }
        }),
        new Paragraph({
          text: "Task Description: Access your authorized profile (ID 1001: Alex Morgan). Tamper with the resource identifier in the route parameter to access the confidential profile of user ID 1002 (Jordan Smith).",
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 3.1 (Attack Execution Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Flag 3.2 (SOC Investigation Flag): ", bold: true }),
            new TextRun({ text: "BLITZ{________________________________________}" })
          ],
          spacing: { after: 100 }
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Investigation Observations (Alert severity, unauthorized object ID, user account compromised):" }),
            new TextRun({ text: "\n_________________________________________________________________________________\n_________________________________________________________________________________" })
          ],
          spacing: { after: 200 }
        }),

        // Completion Checklist
        new Paragraph({
          text: "5. Completion Checklist",
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 200, after: 100 }
        }),
        new Paragraph({ text: "[  ] My Public Connection IP verified in My Connection Information card", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] SQL Injection Attack completed and Flag 1.1 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] SQL Injection SOC event triaged and Flag 1.2 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] Reflected XSS alert('2') executed and Flag 2.1 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] Reflected XSS SOC event triaged and Flag 2.2 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] IDOR profile 1002 accessed and Flag 3.1 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] IDOR SOC event triaged and Flag 3.2 submitted", spacing: { after: 60 } }),
        new Paragraph({ text: "[  ] Challenge Progress reaches 100% (6/6 Stages Complete)", spacing: { after: 120 } })
      ]
    }]
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(path.join(publicDocsDir, 'BLITZ_Cyber_Threats_IOC_Investigation_Questionnaire.docx'), buffer);
  fs.writeFileSync(path.join(rootDocsDir, 'BLITZ_Cyber_Threats_IOC_Investigation_Questionnaire.docx'), buffer);
  console.log('[Docs] Generated BLITZ_Cyber_Threats_IOC_Investigation_Questionnaire.docx');
}

async function generateInstructorKey() {
  const doc = new Document({
    sections: [{
      properties: {},
      children: [
        new Paragraph({
          text: "BLITZ CYBER THREATS & IOC INVESTIGATION LAB",
          heading: HeadingLevel.TITLE,
          spacing: { after: 120 }
        }),
        new Paragraph({
          text: "Confidential Instructor Evaluation Key & Master Solution Manual",
          heading: HeadingLevel.HEADING_2,
          spacing: { after: 240 }
        }),

        new Paragraph({
          text: "1. Master Flags Key (6 Flags Total)",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 200, after: 120 }
        }),

        new Paragraph({
          children: [
            new TextRun({ text: "Challenge 1: SQL Injection Authentication Bypass\n", bold: true }),
            new TextRun({ text: "• Attack Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{sql_auth_bypass_success}\n", font: { name: 'Consolas' } }),
            new TextRun({ text: "• Investigation Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{sql_ioc_7f92kx}\n\n", font: { name: 'Consolas' } }),

            new TextRun({ text: "Challenge 2: Cross-Site Scripting (Reflected XSS)\n", bold: true }),
            new TextRun({ text: "• Attack Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{xss_script_execution_success}\n", font: { name: 'Consolas' } }),
            new TextRun({ text: "• Investigation Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{xss_ioc_4m82qp}\n\n", font: { name: 'Consolas' } }),

            new TextRun({ text: "Challenge 3: Insecure Direct Object Reference (IDOR)\n", bold: true }),
            new TextRun({ text: "• Attack Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{idor_unauthorized_access}\n", font: { name: 'Consolas' } }),
            new TextRun({ text: "• Investigation Flag: ", bold: true }),
            new TextRun({ text: "BLITZ{idor_ioc_9p31mz}\n", font: { name: 'Consolas' } })
          ],
          spacing: { after: 200 }
        }),

        new Paragraph({
          text: "2. Expected Attack & SOC Event Behaviors",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 200, after: 120 }
        }),
        new Paragraph({
          text: "SQL Injection: Student enters payloads such as admin' -- or ' OR '1'='1. The backend authentication verifies the bypass, assigns session role Global Administrator, returns Attack Flag, and generates a HIGH severity event on POST /api/challenge/sqli/login. Triaging the event reveals Investigation Flag BLITZ{sql_ioc_7f92kx}.",
          spacing: { after: 120 }
        }),
        new Paragraph({
          text: "Reflected XSS: Student submits <script>alert('2')</script> in the sandboxed search input. An alert pops up displaying '2', triggering verification and Attack Flag. The backend logs a HIGH severity event on GET /api/challenge/xss/search. Triaging the event reveals Investigation Flag BLITZ{xss_ioc_4m82qp}.",
          spacing: { after: 120 }
        }),
        new Paragraph({
          text: "IDOR: Student loads profile 1001 (Alex Morgan), then alters numeric ID to 1002 (Jordan Smith). The backend detects unauthorized horizontal access, returns Jordan Smith's profile, and generates a CRITICAL severity event on GET /api/challenge/idor/profile/1002. Triaging the event reveals Investigation Flag BLITZ{idor_ioc_9p31mz}.",
          spacing: { after: 200 }
        }),

        new Paragraph({
          text: "3. Source IP Recording & Verification Criteria",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 200, after: 120 }
        }),
        new Paragraph({
          text: "Every actual attack performed by a student is bound to their session and tagged with their real incoming connection IP detected by the backend. Synthetic baseline logs (550+ events) are strictly labeled as SIMULATED TRAINING DATA with is_simulated = 1 using documentation IP blocks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).",
          spacing: { after: 120 }
        }),

        new Paragraph({
          text: "4. Troubleshooting Notes",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 200, after: 120 }
        }),
        new Paragraph({
          text: "• If a student cannot find their event, ensure they enable 'SHOW MY ACTIVITY ONLY' or filter by their connection IP.\n• If investigation flag is missing, ensure the student opens the event details drawer rather than viewing only the table summary.\n• Both stages must be submitted in Challenge Progress to achieve 100% completion.",
          spacing: { after: 120 }
        })
      ]
    }]
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(path.join(publicDocsDir, 'BLITZ_Cyber_Threats_Instructor_Answer_Key.docx'), buffer);
  fs.writeFileSync(path.join(rootDocsDir, 'BLITZ_Cyber_Threats_Instructor_Answer_Key.docx'), buffer);
  console.log('[Docs] Generated BLITZ_Cyber_Threats_Instructor_Answer_Key.docx');
}

async function main() {
  await generateQuestionnaire();
  await generateInstructorKey();
  console.log('[Docs] All Word documents generated successfully!');
}

main().catch(console.error);
