# Proposal change log — `DSCI510_Proposal_Mukherjee` (.docx / .pdf)

Changes requested during Saswata's review. They are collected here and **applied together** once the full read-through is finished, and both formats are regenerated in one pass.

**Current version (October 12):** titled "Anticipating Attacks on Software Flaws", 11 pages, Word and PDF regenerated together. Includes Saswata's edits E1–E6, changes P1–P7, the data preview, P9 (published sources cited inline in Section 5) and P10 (colons after run-in labels). P8 was applied and then reverted at Saswata's request. Saswata's edited Word file is kept as `_archive/proposal_draft_2026-10-02/DSCI510_Proposal_Mukherjee_saswata_edits_2026-10-10.docx`.

| # | Status | Section | Issue raised | Agreed change |
|:--|:--|:--|:--|:--|
| P1 | Applied Oct 10 | §3, "Expected data" | 200,978 looked inconsistent with the ~400K catalogue size and with EPSS's 384,534. Numbers verified as correct: 403,391 = whole NVD catalogue (all years); 200,978 = CVEs published 2016–2024 only (sum of the four counted splits: 99,009 + 30,316 + 30,949 + 40,704); 384,534 = EPSS coverage of the whole catalogue, excluding withdrawn records. The paragraph didn't make the scopes clear. | Replace the paragraph with: "**Expected data.** Of the 403,391 records in the NVD, 200,978 were published between 2016 and 2024, the period used in this project (187,219 after removing withdrawn records). Each record is a nested JSON object containing the description, publication date, publisher, any CVSS scores and weakness classes together with the identity of whoever supplied them, references, and NVD's processing status. The KEV catalogue currently has 1,739 entries with 12 fields each, of which only the CVE ID and the date listed are used in the analysis. EPSS scores almost the entire catalogue (384,534 CVEs as of October 8, 2026 [5]), including every live CVE in my sample." |
| P2 | Applied Oct 10 | §1, para 1 | Edit E2 made "it" ambiguous ("...run by NIST [1]. As of October 9, 2026 it held..." could read as NIST). | "As of October 9, 2026, the NVD held 403,391 records, ..." |
| P3 | Applied Oct 10 | §5, para 1 | Edit E4: "a validation code" is ungrammatical. | "I wrote validation code that tests..." (or "a validation notebook" / "a validation script"). |
| P4 | Applied Oct 10 | References [7] | Stray "7" after "Accessed October 9, 2026." | Delete it. |
| P5 | Applied Oct 10 (kept "Summary." to match the other labels) | Summary label | Edit E1 changed "Summary." to "Summary:"; the other run-in headings ("Intended application.", "Expected data.", "How the sources fit together.") still use a full stop. | Make them consistent: revert to "Summary.", or switch all to colons. |
| P6 | Applied Oct 10 | §8 | Edit E6 says "slightly expanded the scope" and "minimum expectations". Three sources and four questions is well beyond the individual minimum (1 source, 2–3 questions), so "slightly" undersells it, and "minimum expectations" is vaguer than naming the requirement. | e.g. "I have expanded the scope beyond the individual requirement (...)" and "...would still meet the individual-project requirements." |
| P7 | Applied Oct 10 | §3, new "What the data look like" | Saswata asked for a view of what the data will look like. | Added: an abridged NVD JSON record (CVE-2023-21674); Table 3, the same CVE across NVD, KEV and EPSS; Table 4, six real rows of the combined analysis table (three exploited, three not); a short note on missing publisher scores and ID years. Later tables renumbered (old 3–8 → 5–10). |
| P8 | Reverted Oct 12 (Saswata: citing our own validation code as a reference isn't appropriate; Word and PDF restored to the Oct 10 version, PDF regenerated from that Word file) | §5, Preliminary work | Saswata: a reader can't see how the four findings were reached without references. | Each finding now names the validation-code step that produced it, cited as [10], plus an external source: CISA-ADP start date [8, 9], NVD change history [1], NVD prioritisation policy [2], KEV directive [4], EPSS date parameter [5]. Added Table 6, "Evidence for each finding" (finding, steps, what the run showed, supporting source). Later tables renumbered (old 6–10 → 7–11). New references: [8] CISA Vulnrichment repository; [9] Help Net Security, May 9, 2024; [10] validation notebook and run report (Oct 9, 2026). Reference spacing tightened to keep 11 pages. |
| P9 | Applied Oct 12 | §5, Preliminary work | After reverting P8, Saswata agreed to cite only published sources inline (no references to our own code). | Starting from the Oct 10 text: intro names the NVD [1], KEV [3], EPSS [5] and CVE Services [7] interfaces; (a) CISA-ADP/Vulnrichment start date May 2024 [8, 9] and NVD change history [1]; (c) KEV start date tied to BOD 22-01 [4] and the catalogue [3]; (d) EPSS API date parameter [5]. New references [8] CISA Vulnrichment repository and [9] Help Net Security, May 9, 2024. No new tables, no table renumbering; still 11 pages. |
| P10 | Applied Oct 12 | Run-in labels | Saswata changed "Summary." to "Summary:" in Word and chose colons for all such labels (supersedes P5). | Colons after: Summary, Intended application, Expected data, How the sources fit together, What the data look like, and findings (a)–(d) in §5. Unchanged: Q1–Q4 (end in question marks) and table captions ("Table 1."). Edit made on Saswata's Word-saved file; PDF produced with the real Times New Roman and Courier New fonts so it paginates like Word (11 pages); text of PDF checked against the Word file. |

## Saswata's direct edits to the Word file (October 10) — reviewed

| # | Section | Edit | Review |
|:--|:--|:--|:--|
| E1 | Summary | "Summary." → "Summary:" | Fine; consistency point → P5 |
| E2 | §1 | "When I queried the NVD on October 9, 2026 it held" → "As of October 9, 2026 it held" | Fine; ambiguity → P2 |
| E3 | §3 intro | "the access dates are those of the validation run" → "the latest access date for all of them is October 9, 2026" | Fine; matches Table 2 |
| E4 | §5 intro | Removed the mention of the earlier reviewed version, the 17-of-18 result and the no-key test explanation | Fine; Section 5 still stands without them. Grammar → P3 |
| E5 | §4 | "roughly 17 minutes" → "roughly 20 minutes" | Fine: a rounded, slightly conservative version of the notebook's 17-minute estimate |
| E6 | §8 | "kept the scope expected of a two-person team" → "slightly expanded the scope"; "two-person scope" → "minimum expectations" | Fine; wording suggestion → P6 |

## Already applied

| # | Date | Change |
|:--|:--|:--|
| — | Oct 9 | Title changed to "Predicting Which Software Flaws Will Be Attacked", then to **"Anticipating Attacks on Software Flaws"** (both formats). |

## Open from earlier (to confirm during review)

- Course title on the cover: "DSCI 510: Principles of Programming for Data Science" — confirm against the syllabus.
- Date line on the cover: currently "October 2026"; replace with the exact submission date if preferred.
- Charter and notebook walkthrough still carry the old title; update to match if wanted.
