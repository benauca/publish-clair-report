import * as core from '@actions/core';
import * as fs from 'fs';


/**
 * Scanner Report
 */
export interface ScannerReport {
    count: number
    skipped: number
    annotations: Annotation[]
}

export interface Annotation {
    path: string
    start_line: number
    end_line: number
    start_column: number
    end_column: number
    annotation_level: string //'failure' | 'notice' | 'warning'
    title: string
    message: string
    raw_details: string
}

/**
 * Parser Scanner Reports
 * @param reportPaths Location path reports
 * @param severity Severit to filter
 */
export async function parseScannerReports(
    reportPaths: string,
    level: SeverityStrings
): Promise<ScannerReport> {
    return await parseFile(reportPaths, level)
}

/**
 * Json File parser
 * @param file, Clair report as Json file
 * @param severity, Severity
 */
export async function parseFile(
    file: string,
    severity: SeverityStrings): Promise<ScannerReport> {
    let annotations: Annotation[] = []
    let count = 0
    let skipped = 0
    core.info(`Parsing file ${file}`)
    const data: string = fs.readFileSync(file, 'utf8');
    const parseJson = require('parse-json');
    const report = parseJson(data);
    const vulnerabilities = report['vulnerabilities'];

    return await parseVulnerability(vulnerabilities, severity)

}


/**
 * Parser Vulnerability
 * @param vulnerabilities
 */
async function parseVulnerability(
    /* eslint-disable  @typescript-eslint/no-explicit-any */
    vulnerabilities: any,
    severityLevel: SeverityStrings
): Promise<ScannerReport> {
    let count = 0
    let skipped = 0
    const annotations: Annotation[] = []
    core.info("Vulneraibility is " + vulnerabilities)
    for (let vuln in vulnerabilities) {
        if (vulnerabilities.hasOwnProperty(vuln)) {
            const version = (vulnerabilities[vuln]["package"]["version"]) != "" ? (":" + (vulnerabilities[vuln]["package"]["version"])) : "";
            const packageName = (vulnerabilities[vuln]["package"]["name"] + version);
            const name = (vulnerabilities[vuln]["name"]);
            const description: string = (vulnerabilities[vuln]["description"]);
            const links: string = (vulnerabilities[vuln]["links"]);
            const reference: string = (vulnerabilities[vuln]["links"])[0];
            const severity: SeverityStrings = (vulnerabilities[vuln]["normalized_severity"]);
            const fixed_resolved = (vulnerabilities[vuln]["fixed_in_version"]);

            if (Severity[severity] >= Severity[severityLevel]) {
                annotations.push({
                    path: links.split(" ")[0],
                    start_line: 0,
                    end_line: 0,
                    start_column: 0,
                    end_column: 0,
                    annotation_level: await mappingSeverity(severity),
                    title: (version.length>0)?( packageName + " [ " + version + " ]"):packageName,
                    message:  (fixed_resolved.length>0)?( name + " \nFixed Resolved in: [ " + fixed_resolved + " ]"):name,
                    raw_details: description
                })
            }

        }
    }
    core.info("Annotations is: " + annotations.length)
    return {count, skipped, annotations}
}

/**
 * Convert severity to  annotation level
 * 'failure' | 'notice' | 'warning'
 * @param severity
 */
export async function mappingSeverity(severity: string): Promise<string> {
    switch (severity.toLowerCase()) {
        case "unknown":
            return 'notice'
        case "negligible":
            return 'notice'
        case "low":
            return 'notice'
        case "medium":
            return 'warning'
        case "high":
            return 'failure'
        case "critical":
            return 'failure'
        case "defcon1":
            return 'failure'
        default:
            return 'notice'
    }
}

export enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
    Defcon1

}
/**
 * This is equivalent to:
 * type LogLevelStrings = 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';
 */
export type SeverityStrings = keyof typeof Severity;
