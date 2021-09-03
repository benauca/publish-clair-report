import * as core from '@actions/core';
import * as github from '@actions/github'
import {parseScannerReports} from "./ClairReport";

export async function run(): Promise<void> {

    const checkName = core.getInput('check_name')
    const commit = core.getInput('commit')
    const requireScans: boolean = core.getInput('require_scans') === 'true'
    const severityLevel = core.getInput('severity_level')
    const publishSummary: boolean = core.getInput('publish_summary') === 'true'

    try {
        core.startGroup(` Getting input values`);
        let summary = core.getInput('summary')
        const reportPaths = core.getInput('report_paths')
        core.info("Filter By security: " + severityLevel)

        const token =
            core.getInput('token') ||
            core.getInput('github_token') ||
            process.env.GITHUB_TOKEN

        const failWithVulnerabilities: boolean = core.getInput("fail_with_vulnerabilities") === 'true'
        if (!token) {
            core.setFailed('Token is mandatory to execute this action.')
            return
        }
        core.endGroup()

        core.startGroup(` Process Scan Reports...`)
        let clairReport
        try {
            // @ts-ignore
            clairReport = await parseScannerReports(reportPaths, severityLevel)
        }catch (error) {
            core.warning(error.message)
            if(requireScans){
                core.setFailed(error.message)
            }
            return
        }
        const vulnerabilities = clairReport.count > 0;
        core.info(`Total Vulnerabilities: ` + clairReport.annotations.length)
        core.info(`Clair report count: ` + clairReport.count)
        const title = clairReport.annotations.length > 0
            ? `${clairReport.annotations.length} Vulnerabilities founds.`
            : 'No Vulnerabilities found with level ' + severityLevel +' or higher!.'
        core.info(`${title}`)

        const pullRequest = github.context.payload.pull_request
        const link = (pullRequest && pullRequest.html_url) || github.context.ref
        const conclusion: 'success' | 'failure' =
            failWithVulnerabilities && (clairReport.annotations.filter(value => value.annotation_level === 'failure')).length > 0
                ? 'failure'
                : 'success'
        const status: 'completed' = 'completed'
        const head_sha =
            commit || (pullRequest && pullRequest.head.sha) || github.context.sha
        core.info(
            `ℹ️ Posting status '${status}' with conclusion '${conclusion}' to ${link} (sha: ${head_sha})`
        )

        summary +=
            "\nTotal: Vulnerabilities: " + clairReport.count +
            "\n\t 💥 Defcon1 Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Defcon1") +
            "\n\t 🔥 Critical Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Critical") +
            "\n\t 💢 High Vulnerabilities: " + clairReport.summaryVulnerabilities.get("High") +
            "\n\t ☀ Medium Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Medium") +
            "\n\t ☔ Low Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Low") +
            "\n\t ☁ Negligible Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Negligible") +
            "\n\t 🌊 Unknown Vulnerabilities: " + clairReport.summaryVulnerabilities.get("Unknown")

        const createCheckRequest = {
            ...github.context.repo,
            name: checkName,
            head_sha,
            status,
            conclusion,
            output: {
                title,
                summary,
                annotations: clairReport.annotations.slice(0, 50)
            }
        }
        core.debug(JSON.stringify(createCheckRequest, null, 2))
        core.endGroup()

        core.startGroup(`🚀 Publish results`)
        core.info(title);
        core.info(summary);
        if (conclusion === 'failure' || (conclusion === 'success' && publishSummary))
        {
            try {
                const octokit = github.getOctokit(token)
                await octokit.rest.checks.create(createCheckRequest)

                if (conclusion === 'failure') {
                    core.setFailed(
                        `Vulnerabilities reported ${clairReport.annotations.length} failures`
                    )
                }
            } catch (error) {
                core.error(
                    `Failed to create checks using the provided token. (${error})`
                )
                core.warning(
                    `This usually indicates insufficient permissions.`
                )
            }
        }
        core.endGroup()
    } catch (error) {
        core.setFailed(error.message)
    }
}

run()
