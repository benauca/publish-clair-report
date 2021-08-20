"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var core = require("@actions/core");
var github = require("@actions/github");
var ClairReport_1 = require("./ClairReport");
function run() {
    return __awaiter(this, void 0, void 0, function () {
        var summary, reportPaths, suiteRegex, token, checkName, commit, failOnFailure, requireTests, clairReport, vulnerabilities, title, pullRequest, link, conclusion, status_1, head_sha, createCheckRequest, octokit, error_1, error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 6, , 7]);
                    core.startGroup(" Getting input values");
                    summary = core.getInput('summary');
                    reportPaths = core.getInput('report_paths');
                    suiteRegex = core.getInput('suite_regex');
                    token = core.getInput('token') ||
                        core.getInput('github_token') ||
                        process.env.GITHUB_TOKEN;
                    if (!token) {
                        core.setFailed('Token is mandatory to execute this action.');
                        return [2 /*return*/];
                    }
                    checkName = core.getInput('check_name');
                    commit = core.getInput('commit');
                    failOnFailure = core.getInput('fail_on_failure') === 'true';
                    requireTests = core.getInput('require_tests') === 'true';
                    core.endGroup();
                    core.startGroup(" Process Scan Reports...");
                    return [4 /*yield*/, ClairReport_1.parseScannerReports(reportPaths)];
                case 1:
                    clairReport = _a.sent();
                    vulnerabilities = clairReport.count > 0 || clairReport.skipped > 0;
                    title = vulnerabilities
                        ? clairReport.count + " tests run, " + clairReport.skipped + " skipped, " + clairReport.annotations.length + " founds."
                        : 'No Vulnerabilities found!';
                    core.info("" + title);
                    if (!vulnerabilities) {
                        if (requireTests) {
                            core.setFailed(' No Vulnerabilities found');
                        }
                        return [2 /*return*/];
                    }
                    pullRequest = github.context.payload.pull_request;
                    link = (pullRequest && pullRequest.html_url) || github.context.ref;
                    conclusion = vulnerabilities && clairReport.annotations.length === 0
                        ? 'success'
                        : 'failure';
                    status_1 = 'completed';
                    head_sha = commit || (pullRequest && pullRequest.head.sha) || github.context.sha;
                    core.info("\u2139\uFE0F Posting status '" + status_1 + "' with conclusion '" + conclusion + "' to " + link + " (sha: " + head_sha + ")");
                    createCheckRequest = __assign({}, github.context.repo, { name: checkName, head_sha: head_sha,
                        status: status_1,
                        conclusion: conclusion, output: {
                            title: title,
                            summary: summary,
                            annotations: clairReport.annotations.slice(0, 50)
                        } });
                    core.debug(JSON.stringify(createCheckRequest, null, 2));
                    core.endGroup();
                    core.startGroup("\uD83D\uDE80 Publish results");
                    _a.label = 2;
                case 2:
                    _a.trys.push([2, 4, , 5]);
                    octokit = github.getOctokit(token);
                    return [4 /*yield*/, octokit.rest.checks.create(createCheckRequest)];
                case 3:
                    _a.sent();
                    if (failOnFailure && conclusion === 'failure') {
                        core.setFailed("Vulneraabilites reported " + clairReport.annotations.length + " failures");
                    }
                    return [3 /*break*/, 5];
                case 4:
                    error_1 = _a.sent();
                    core.error("Failed to create checks using the provided token. (" + error_1 + ")");
                    core.warning("This usually indicates insufficient permissions.");
                    return [3 /*break*/, 5];
                case 5:
                    core.endGroup();
                    return [3 /*break*/, 7];
                case 6:
                    error_2 = _a.sent();
                    core.setFailed(error_2.message);
                    return [3 /*break*/, 7];
                case 7: return [2 /*return*/];
            }
        });
    });
}
exports.run = run;
run();
