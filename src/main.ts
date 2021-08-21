import * as core from '@actions/core';
import * as github from '@actions/github'
import {parseScannerReports} from "./ClairReport";

export async function run(): Promise<void> {

    try {
        core.startGroup(` Getting input values`);
        const summary = core.getInput('summary')
        //const reportPaths = core.getInput('report_paths')
        const token =
            core.getInput('token') ||
            core.getInput('github_token') ||
            process.env.GITHUB_TOKEN

        if (!token) {
            core.setFailed('Token is mandatory to execute this action.')
            return
        }
        const checkName = core.getInput('check_name')
        const commit = core.getInput('commit')
        const failOnFailure = core.getInput('fail_on_failure') === 'true'
        const requireTests = core.getInput('require_tests') === 'true'

        core.endGroup()

        core.startGroup(` Process Scan Reports...`)
        const reportPaths:any = "assets/clair-report/*.json"
        console.log("--" + reportPaths);
        const clairReport = await parseScannerReports(reportPaths);
        const vulnerabilities = clairReport.count > 0 || clairReport.skipped > 0;

        const title = vulnerabilities
            ? `${clairReport.count} tests run, ${clairReport.skipped} skipped, ${clairReport.annotations.length} founds.`
            : 'No Vulnerabilities found!'
        core.info(`${title}`)

        if (!vulnerabilities) {
            if (requireTests) {
                core.setFailed(' No Vulnerabilities found')
            }
            return
        }
        const pullRequest = github.context.payload.pull_request
        const link = (pullRequest && pullRequest.html_url) || github.context.ref
        const conclusion: 'success' | 'failure' =
            vulnerabilities && clairReport.annotations.length === 0
                ? 'success'
                : 'failure'
        const status: 'completed' = 'completed'
        const head_sha =
            commit || (pullRequest && pullRequest.head.sha) || github.context.sha
        core.info(
            `ℹ️ Posting status '${status}' with conclusion '${conclusion}' to ${link} (sha: ${head_sha})`
        )

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

        try {
            const octokit = github.getOctokit(token)
            await octokit.rest.checks.create(createCheckRequest)

            if (failOnFailure && conclusion === 'failure') {
                core.setFailed(
                    `Vulneraabilites reported ${clairReport.annotations.length} failures`
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
        core.endGroup()
    } catch (error) {
        core.setFailed(error.message)
    }
}
run()
