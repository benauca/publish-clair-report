import * as core from '@actions/core';
import * as glob from '@actions/glob';
import * as fs from 'fs';
// @ts-ignore
import * as parseJson from 'parse-json';

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
    annotation_level: 'failure' | 'notice' | 'warning'
    title: string
    message: string
    raw_details: string
}


/**
 * Json File parser
 * @param file, Clair report as Json file
 */
export async function parseFile(
    file: string): Promise<ScannerReport> {

    core.info(`Parsing file ${file}`)
    const data: string = fs.readFileSync(file, 'utf8')
    core.info(data.length>0?"data has Content." : " Upps.............");
    const report = parseJson(data, {compact: true});
    const vulnerabilities = report['vulnerabilities'];
    return parseVulnerability(vulnerabilities)
}

/**
 * Parser Scanner Reports
 * @param reportPaths
 */
export async function parseScannerReports(
    reportPaths: string
): Promise<ScannerReport> {
    const globber = await glob.create(reportPaths, {followSymbolicLinks: false})
    let annotations: Annotation[] = []
    let count = 0
    let skipped = 0
    for await (const file of globber.globGenerator()) {
        const {
            count: c,
            skipped: s,
            annotations: a
        } = await parseFile(file)
        if (c === 0) continue
        count += c
        skipped += s
        annotations = annotations.concat(a)
    }
    return {count, skipped, annotations}
}

/**
 * Parser Vulnerability
 * @param vulnerabilities
 */
async function parseVulnerability(
    /* eslint-disable  @typescript-eslint/no-explicit-any */
    vulnerabilities: any
): Promise<ScannerReport> {
    let count = 0
    let skipped = 0
    const annotations: Annotation[] = []
    core.info("Vulneraibility is " + vulnerabilities)
    for (let vuln in vulnerabilities) {
        if (vulnerabilities.hasOwnProperty(vuln)) {
            const version = (vulnerabilities[vuln]["package"]["version"]) != "" ? (":" + (vulnerabilities[vuln]["package"]["version"])) : "";
            const title = (vulnerabilities[vuln]["package"]["name"] + version);
            const name = (vulnerabilities[vuln]["name"]);
            const description:string = (vulnerabilities[vuln]["description"]);
            const links:string = (vulnerabilities[vuln]["links"]);
            const severity = (vulnerabilities[vuln]["normalized_severity"]);
            const fixed_resolved = (vulnerabilities[vuln]["fixed_in_version"]);
            core.info("======================");
            core.info("\t" + title);
            core.info("\n\t\t" + name);
            core.info("\n\t\t" + description);
            core.info("\n\t\t" + links);
            core.info("\n\t\t" + severity);
            core.info("\n\t\tResolved in " + fixed_resolved);

            core.info("======================");
             annotations.push({
                path: links.split(' ')[0],
                start_line: 0,
                end_line: 0,
                start_column: 0,
                end_column: 0,
                annotation_level: 'warning',
                title: version + ": " + title,
                message: name + "\nFixed Resolved: " + fixed_resolved + "Info: \n" + links,
                raw_details: description
            })


        }
    }
    return {count, skipped, annotations}
}
