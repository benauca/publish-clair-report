//@ts-ignore
import parseJson = require('parse-json');
import * as core from '@actions/core';
import * as glob from '@actions/glob';
import * as fs from 'fs';


/**
 * Scanner Report
 */
export interface ScannerReport {

    /**
     * Total number  of Vulnerabilities
     */
    count: number
    summaryVulnerabilities: Map<string, number>
    annotations: Annotation[]
}

/**
 * Represent an GitHub annotation
 */
export interface Annotation {
    /**
     * Vulnerabilitie Link
     */
    path: string
    start_line: number
    end_line: number
    start_column: number
    end_column: number
    /**
     * Annotation Level
     * 'failure' | 'notice' | 'warning'
     */
    annotation_level: string
    /**
     * Title
     */
    title: string
    /**
     * Message
     */
    message: string
    /**
     * Vulnerability description
     */
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
    const globber = await glob.create(reportPaths, {followSymbolicLinks: false})
    const file = await globber.glob();

    return await parseFile(file.length > 0 ? file[0] : reportPaths, level)
}

/**
 * Json File parser
 * @param file, Clair report as Json file
 * @param severity, Severity
 */
async function parseFile(
    file: string,
    severity: SeverityStrings): Promise<ScannerReport> {
    core.info(`Parsing file ${file}`)
    const data: string = fs.readFileSync(file, 'utf8');
    const report = parseJson(data);
    const vulnerabilities = report['vulnerabilities'];

    return await parseVulnerability(vulnerabilities, severity);

}


/**
 * Parser Vulnerability
 * @param vulnerabilities
 */
async function parseVulnerability(
    vulnerabilities: any,
    severityLevel: SeverityStrings
): Promise<ScannerReport> {

    let count: number = 0;
    let summaryVulnerabilities = new Map<string, number>();
    summaryVulnerabilities.set("Unknown", 0)
    summaryVulnerabilities.set("Negligible", 0)
    summaryVulnerabilities.set("Low", 0)
    summaryVulnerabilities.set("Medium", 0)
    summaryVulnerabilities.set("High", 0)
    summaryVulnerabilities.set("Critical", 0)
    summaryVulnerabilities.set("Defcon1", 0)

    const annotations: Annotation[] = []
    core.info("Vulneraibility is " + vulnerabilities)
    for (let vuln in vulnerabilities) {
        count++
        if (vulnerabilities.hasOwnProperty(vuln)) {
            const version = (vulnerabilities[vuln]["package"]["version"]) != "" ? (vulnerabilities[vuln]["package"]["version"]) : "";
            const packageName = (vulnerabilities[vuln]["package"]["name"]);
            const name = (vulnerabilities[vuln]["name"]);
            const description: string = (vulnerabilities[vuln]["description"]);
            const links: string = (vulnerabilities[vuln]["links"]);
            const reference: string = (vulnerabilities[vuln]["links"])[0];
            const severity: SeverityStrings = (vulnerabilities[vuln]["normalized_severity"]);
            //@ts-ignore
            summaryVulnerabilities.set(severity, summaryVulnerabilities.get(severity) + 1)
            const fixed_resolved = (vulnerabilities[vuln]["fixed_in_version"]);

            if (Severity[severity] >= Severity[severityLevel]) {
                annotations.push({
                    path: links.split(" ")[0],
                    start_line: 0,
                    end_line: 0,
                    start_column: 0,
                    end_column: 0,
                    annotation_level: await mappingSeverity(severity),
                    title: (version.length > 0) ? (packageName + " [ " + version + " ]") : packageName,
                    message: (fixed_resolved.length > 0) ? (name + " \nFixed Resolved in: [ " + fixed_resolved + " ]") : name,
                    raw_details: description
                })
            }

        }
    }
    annotations.sort((annotation, other) => (annotation.annotation_level > other.annotation_level) ? 1 : -1)
    core.info("Annotations is: " + annotations.length)
    return {count, summaryVulnerabilities, annotations}
}

/**
 * Convert severity to  annotation level
 * 'failure' | 'notice' | 'warning'
 * @param severity
 */
async function mappingSeverity(severity: string): Promise<string> {
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

/**
 * Severity Clair
 */
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
 * type SeverityStrings = 'Unknown' | 'Negligible' | 'Low' | 'Medium' | 'High' | 'Critical' | 'Defcon1' ;
 */
export type SeverityStrings = keyof typeof Severity;
