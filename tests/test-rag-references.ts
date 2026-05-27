import assert from "node:assert/strict";
import {
  citedContextIds,
  formatRagReferences,
  pageNumberFromContext,
  ragReferenceHref,
  stripGeneratedSourceSection,
} from "../src/lib/rag-references";

function testCitationFilteringAndLinks() {
  const answer = "RSA와 ECC가 공개키 암호의 대표 방식입니다 [2].";
  const refs = formatRagReferences(
    [
      { id: 1, source: "security/intro.pdf", page: 1 },
      { id: 2, source: "security/public key.pdf", page: 22, locator: "page 22" },
      { id: 3, source: "security/other.pdf", page: 99 },
    ],
    answer,
    "inbox"
  );

  assert(refs.includes("security/public key.pdf"));
  assert(refs.includes("action=view"));
  assert(refs.includes("path=security%2Fpublic+key.pdf"));
  assert(refs.includes("#page=22"));
  assert(!refs.includes("security/intro.pdf"));
  console.log("testCitationFilteringAndLinks PASSED");
}

function testFallbackLimitsReferences() {
  const refs = formatRagReferences(
    [
      { id: 1, source: "a.pdf", page: 1 },
      { id: 2, source: "b.pdf", page: 2 },
      { id: 3, source: "c.pdf", page: 3 },
      { id: 4, source: "d.pdf", page: 4 },
    ],
    "인용이 없는 답변입니다.",
    "inbox"
  );

  assert(refs.includes("a.pdf"));
  assert(refs.includes("c.pdf"));
  assert(!refs.includes("d.pdf"));
  console.log("testFallbackLimitsReferences PASSED");
}

function testSourceSectionStripping() {
  const answer = "본문입니다 [1].\n\n**출처**\n[1] a.pdf";

  assert.equal(stripGeneratedSourceSection(answer), "본문입니다 [1].");
  console.log("testSourceSectionStripping PASSED");
}

function testPageParsing() {
  assert.equal(pageNumberFromContext({ source: "a.pdf", locator: "page 83" }), 83);
  assert.equal(pageNumberFromContext({ source: "a.pdf", page: "22" }), 22);
  assert.equal(pageNumberFromContext({ source: "a.txt", locator: "document" }), null);
  console.log("testPageParsing PASSED");
}

function testMissingSourceHasNoHref() {
  assert.equal(ragReferenceHref("inbox", { id: 1 }), null);
  assert.deepEqual([...citedContextIds("참조 [3], [1], [x]")], [3, 1]);
  console.log("testMissingSourceHasNoHref PASSED");
}

testCitationFilteringAndLinks();
testFallbackLimitsReferences();
testSourceSectionStripping();
testPageParsing();
testMissingSourceHasNoHref();
console.log("\nAll tests PASSED");
