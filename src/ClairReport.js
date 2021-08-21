"use strict";
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
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
Object.defineProperty(exports, "__esModule", { value: true });
var core = require("@actions/core");
var glob = require("@actions/glob");
var fs = require("fs");
// @ts-ignore
var parseJson = require("parse-json");
/**
 * Json File parser
 * @param file, Clair report as Json file
 */
function parseFile(file) {
    return __awaiter(this, void 0, void 0, function () {
        var data, report, vulnerabilities;
        return __generator(this, function (_a) {
            core.info("Parsing file " + file);
            data = fs.readFileSync(file, 'utf8');
            core.info(data.length > 0 ? "data has Content." : " Upps.............");
            report = parseJson(data, { compact: true });
            vulnerabilities = report['vulnerabilities'];
            return [2 /*return*/, parseVulnerability(vulnerabilities)];
        });
    });
}
exports.parseFile = parseFile;
/**
 * Parser Scanner Reports
 * @param reportPaths
 */
function parseScannerReports(reportPaths) {
    return __awaiter(this, void 0, void 0, function () {
        var e_1, _a, globber, annotations, count, skipped, _b, _c, file, _d, c, s, a, e_1_1;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0: return [4 /*yield*/, glob.create(reportPaths, { followSymbolicLinks: false })];
                case 1:
                    globber = _e.sent();
                    annotations = [];
                    count = 0;
                    skipped = 0;
                    _e.label = 2;
                case 2:
                    _e.trys.push([2, 8, 9, 14]);
                    _b = __asyncValues(globber.globGenerator());
                    _e.label = 3;
                case 3: return [4 /*yield*/, _b.next()];
                case 4:
                    if (!(_c = _e.sent(), !_c.done)) return [3 /*break*/, 7];
                    file = _c.value;
                    return [4 /*yield*/, parseFile(file)];
                case 5:
                    _d = _e.sent(), c = _d.count, s = _d.skipped, a = _d.annotations;
                    if (c === 0)
                        return [3 /*break*/, 6];
                    count += c;
                    skipped += s;
                    annotations = annotations.concat(a);
                    _e.label = 6;
                case 6: return [3 /*break*/, 3];
                case 7: return [3 /*break*/, 14];
                case 8:
                    e_1_1 = _e.sent();
                    e_1 = { error: e_1_1 };
                    return [3 /*break*/, 14];
                case 9:
                    _e.trys.push([9, , 12, 13]);
                    if (!(_c && !_c.done && (_a = _b.return))) return [3 /*break*/, 11];
                    return [4 /*yield*/, _a.call(_b)];
                case 10:
                    _e.sent();
                    _e.label = 11;
                case 11: return [3 /*break*/, 13];
                case 12:
                    if (e_1) throw e_1.error;
                    return [7 /*endfinally*/];
                case 13: return [7 /*endfinally*/];
                case 14: return [2 /*return*/, { count: count, skipped: skipped, annotations: annotations }];
            }
        });
    });
}
exports.parseScannerReports = parseScannerReports;
/**
 * Parser Vulnerability
 * @param vulnerabilities
 */
function parseVulnerability(
/* eslint-disable  @typescript-eslint/no-explicit-any */
vulnerabilities) {
    return __awaiter(this, void 0, void 0, function () {
        var count, skipped, annotations, vuln, version, title, name_1, description, links, severity, fixed_resolved;
        return __generator(this, function (_a) {
            count = 0;
            skipped = 0;
            annotations = [];
            core.info("Vulneraibility is " + vulnerabilities);
            for (vuln in vulnerabilities) {
                if (vulnerabilities.hasOwnProperty(vuln)) {
                    version = (vulnerabilities[vuln]["package"]["version"]) != "" ? (":" + (vulnerabilities[vuln]["package"]["version"])) : "";
                    title = (vulnerabilities[vuln]["package"]["name"] + version);
                    name_1 = (vulnerabilities[vuln]["name"]);
                    description = (vulnerabilities[vuln]["description"]);
                    links = (vulnerabilities[vuln]["links"]);
                    severity = (vulnerabilities[vuln]["normalized_severity"]);
                    fixed_resolved = (vulnerabilities[vuln]["fixed_in_version"]);
                    core.info("======================");
                    core.info("\t" + title);
                    core.info("\n\t\t" + name_1);
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
                        message: name_1 + "\nFixed Resolved: " + fixed_resolved + "Info: \n" + links,
                        raw_details: description
                    });
                }
            }
            return [2 /*return*/, { count: count, skipped: skipped, annotations: annotations }];
        });
    });
}
