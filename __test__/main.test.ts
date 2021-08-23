import * as core from '@actions/core'
import * as github from '@actions/github'
import {WebhookPayload} from '@actions/github/lib/interfaces'
//const fixtures = require("@octokit/fixtures");
import {run} from '../src/main'

beforeEach(() => {

    jest.resetModules()
    process.env['GITHUB_REPOSITORY'] = 'benauca/test'
    process.env['INPUT_SEVERITY_LEVEL'] = 'High';
    process.env['INPUT_REPORT_PATHS'] = 'assets/clair-report/ubuntu*.json'
    process.env['INPUT_TOKEN'] = 'myToken'
    github.context.payload = {
        action: 'opened',
        pull_request: {
            number: 1,
            head: {
                label: "Codertocat:changes",
                ref: "changes",
                sha: "ec26c3e57ca3a959ca5aad62de7213c562f8c821"
            },
            html_url: "https://github.com/Codertocat"
        },

    } as WebhookPayload
})

afterEach(() => {
    delete process.env['INPUT_SEVERITY_LEVEL'];
    delete process.env['INPUT_REPORT_PATHS'];
    delete process.env['INPUT_TOKEN'];
    delete process.env['GITHUB_REPOSITORY'];

})
describe('test main', () => {
    it('should outputs a debug message', async () => {
        const debugMock = jest.spyOn(core, 'info')
        await run()
        expect(debugMock).toHaveBeenCalledWith("Filter By security: High");
        expect(debugMock).toHaveBeenCalledWith(`Total Vulnerabilities: ` + 4);
        expect(debugMock).toHaveBeenCalledWith(`Clair report count: ` + 603);
        expect(debugMock).toHaveBeenCalledWith('4 Vulnerabilities founds.')

    })

    it('should publish annotations in github', async () => {
        const debugMock = jest.spyOn(core, 'info')
        await run()
        expect(debugMock).toHaveBeenCalledWith("ℹ️ Posting status 'completed' with conclusion 'failure' to https://github.com/Codertocat (sha: ec26c3e57ca3a959ca5aad62de7213c562f8c821)");

    });

    it('should not found vulnerabilities', async () => {
        process.env['INPUT_REPORT_PATHS'] = 'assets/clair-report/should_finish_success_if_not_exist_vulnerabilities.json'
        const debugMock = jest.spyOn(core, 'info')
        await run()
        expect(debugMock).toHaveBeenCalledWith("No Vulnerabilities found!");

    });

    it('should finish success if not exist vulnerabilities', async () => {
        process.env['INPUT_REPORT_PATHS'] = 'assets/clair-report/should_finish_success_if_not_exist_vulnerabilities.json'
        process.env['INPUT_SEVERITY_LEVEL'] = 'Negligible';
        const debugMock = jest.spyOn(core, 'info')
        await run()
        expect(debugMock).toHaveBeenCalledWith("ℹ️ Posting status 'completed' with conclusion 'success' to https://github.com/Codertocat (sha: ec26c3e57ca3a959ca5aad62de7213c562f8c821)");

    });

    it('should finish ko if require_scan and report not found', async () => {
        process.env['INPUT_REPORT_PATHS'] = 'assets/clair-report/not_found.json'
        process.env['INPUT_SEVERITY_LEVEL'] = 'Negligible';
        process.env['INPUT_REQUIRE_SCAN'] = 'true';
        const debugMock = jest.spyOn(core, 'setFailed')
        await run()
        expect(debugMock).toHaveBeenCalledWith("ENOENT: no such file or directory, open 'assets/clair-report/not_found.json'");
    });
})