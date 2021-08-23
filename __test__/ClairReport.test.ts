import {parseScannerReports} from "../src/ClairReport";


describe('parseScannerReports', () => {
    it('should parse High results', async () => {
        const {
            count,
            summaryVulnerabilities,
            annotations
        } = await parseScannerReports(
            "assets/clair-report/ubuntu-14.04.local.json", "High");

        expect(count).toBe(603);
        expect(summaryVulnerabilities.size).toBe(7);
        expect(annotations.length).toBe(4);
    });

    it('should parse Low results and excludes Negligible vulnerabilities ', async () => {
        const {
            count,
            summaryVulnerabilities,
            annotations
        } = await parseScannerReports(
            "assets/clair-report/ubuntu-14.04.local.json", "Low");

        expect(count).toBe(603);
        expect(summaryVulnerabilities.size).toBe(7);
        expect(summaryVulnerabilities.get("Negligible")).toBe(130);
        expect(annotations.length).toBe(473);
    });

    it('should parse results and include a brief summary', async () => {
        const {
            count,
            summaryVulnerabilities,
            annotations
        } = await parseScannerReports(
            "assets/clair-report/ubuntu-14.04.local.json", "High");

        expect(count).toBe(603);
        expect(summaryVulnerabilities.size).toBe(7);
        expect(summaryVulnerabilities.get("Defcon1")).toBe(0);
        expect(summaryVulnerabilities.get("Critical")).toBe(0);
        expect(summaryVulnerabilities.get("High")).toBe(4);
        expect(summaryVulnerabilities.get("Medium")).toBe(192);
        expect(summaryVulnerabilities.get("Low")).toBe(277);
        expect(summaryVulnerabilities.get("Negligible")).toBe(130);
        expect(annotations.length).toBe(4);
    });

    it('should parse with glob format file ', async () => {
        const {
            count,
            summaryVulnerabilities,
            annotations
        } = await parseScannerReports(
            "assets/clair-report/ubuntu-*.json", "High");

        expect(count).toBe(603);
        expect(summaryVulnerabilities.size).toBe(7);
        expect(summaryVulnerabilities.get("Defcon1")).toBe(0);
        expect(summaryVulnerabilities.get("Critical")).toBe(0);
        expect(summaryVulnerabilities.get("High")).toBe(4);
        expect(summaryVulnerabilities.get("Medium")).toBe(192);
        expect(summaryVulnerabilities.get("Low")).toBe(277);
        expect(summaryVulnerabilities.get("Negligible")).toBe(130);
        expect(annotations.length).toBe(4);
    });

    it('should fail with file not found ', async () => {
        try {
            await parseScannerReports(
                "assets/clair-report/NotExits.json", "High")
        } catch (e) {
            expect(e.message).toBe("ENOENT: no such file or directory, open \'assets/clair-report/NotExits.json\'");
        }

    });

    it('should get Annotations ', async () => {
        const {
            annotations
        } = await parseScannerReports(
            "assets/clair-report/anotations-test01.json", "High");
        expect(annotations.length).toBe(2);
        expect(annotations[1].annotation_level).toBe("failure")
        expect(annotations[1].path).toBe("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5276");
        expect(annotations[1].title).toBe("libstdc++6 [ 1.0 ]");
        expect(annotations[1].message).toBe("CVE-2015-5276 on Ubuntu 14.04 LTS (trusty) - High.");


        expect(annotations[0].annotation_level).toBe("failure")
        expect(annotations[0].title).toBe("libstdc++6");
        expect(annotations[0].path).toBe("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5276");
        expect(annotations[0].message).toBe("CVE-2015-5276 on Ubuntu 14.04 LTS (trusty) - High. \n" +
            "Fixed Resolved in: [ 0:1.0.1f-1ubuntu2.27+esm2 ]");
    });

    it('should get Annotations must be ordered by annotation_level', async () => {
        const {
            count,
            summaryVulnerabilities,
            annotations
        } = await parseScannerReports(
            "assets/clair-report/ubuntu*.json", "Low");
        expect(annotations[0].annotation_level).toBe("failure");
        expect(annotations[1].annotation_level).toBe("failure");
        expect(annotations[2].annotation_level).toBe("failure");
        expect(annotations[3].annotation_level).toBe("failure");
        expect(annotations[4].annotation_level).toBe("notice");
        expect(count).toBe(603);
        expect(summaryVulnerabilities.size).toBe(7);
        expect(annotations.length).toBe(473);
    });
});
