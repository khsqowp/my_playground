import { createRequire } from "module";
const require = createRequire(import.meta.url);
const pdf = require("pdf-parse");

/**
 * 폴더명 정규화: 각 세그먼트에서 공백·언더스코어 제거
 * "웹 보안" → "웹보안", "네트워크_분析" → "네트워크분析"
 */
export function normalizeFolder(folder: string): string {
  return folder
    .split("/")
    .map((seg) => seg.trim().replace(/[\s_]+/g, ""))
    .filter(Boolean)
    .join("/")
    .replace(/\/+/g, "/");
}

/** 파일명/확장자로 폴더를 추론 (텍스트 추출 불가 파일 fallback) */
export function inferFolderFromFilename(fileName: string, ext: string): string {
  const name = fileName.toLowerCase().replace(/\.[^.]+$/, "");

  const keywordMap: [string[], string][] = [
    [["typescript", " ts ", "_ts_", "-ts-"], "개발/TypeScript"],
    [["javascript", " js ", "_js_", "-js-"], "개발/JavaScript"],
    [["python", " py ", "_py_"], "개발/Python"],
    [["react", "nextjs", "next.js", "vue", "angular"], "개발/프론트엔드"],
    [["docker", "kubernetes", "k8s", "devops", "ci-cd", "cicd"], "개발/DevOps"],
    [["database", "db", "sql", "mysql", "postgres", "mongodb"], "개발/데이터베이스"],
    [["api", "rest", "graphql", "swagger", "openapi"], "개발/API"],
    [["report", "보고서", "리포트"], "문서/보고서"],
    [["meeting", "회의", "미팅", "minutes"], "문서/회의록"],
    [["proposal", "기획", "제안"], "문서/기획"],
    [["resume", "이력서", "cv", "portfolio", "포트폴리오"], "문서/이력서"],
    [["lecture", "강의", "tutorial", "튜토리얼", "course"], "학습/강의자료"],
    [["note", "노트", "study", "공부", "학습"], "학습/노트"],
    [["quiz", "퀴즈", "exam", "시험", "test"], "학습/시험"],
    [["design", "디자인", "ui", "ux", "figma", "wireframe"], "디자인"],
    [["data", "dataset", "분석", "analysis", "chart", "graph"], "데이터/분析"],
    [["log", "로그", "backup", "백업"], "시스템/로그"],
    [["config", "설정", "settings", "env"], "시스템/설정"],
  ];

  for (const [keywords, folder] of keywordMap) {
    if (keywords.some((k) => name.includes(k))) return folder;
  }

  const extMap: Record<string, string> = {
    pdf: "문서/PDF",
    pptx: "문서/발표자료",
    xlsx: "데이터/스프레드시트",
    docx: "문서",
    zip: "아카이브",
    txt: "문서/텍스트",
    md: "개발/문서",
  };
  return extMap[ext] || "미분류";
}

/** 파일 버퍼에서 텍스트 추출 */
export async function extractTextContent(buffer: Buffer, ext: string, limit = 3000): Promise<string | null> {
  try {
    if (ext === "txt" || ext === "md") {
      const text = buffer.toString("utf-8");
      return limit > 0 ? text.substring(0, limit) : text;
    }
    if (ext === "pdf") {
      const data = await pdf(buffer);
      return limit > 0 ? data.text.substring(0, limit) : data.text;
    }
    if (ext === "docx") {
      const mammoth = await import("mammoth");
      const result = await mammoth.extractRawText({ buffer });
      return limit > 0 ? result.value.substring(0, limit) : result.value;
    }
    if (ext === "xlsx") {
      const XLSX = await import("xlsx");
      const workbook = XLSX.read(buffer, { type: "buffer" });
      let text = "";
      for (const sheetName of workbook.SheetNames) {
        const sheet = workbook.Sheets[sheetName];
        const csv = XLSX.utils.sheet_to_csv(sheet);
        text += `[${sheetName}]\n${csv}\n\n`;
        if (limit > 0 && text.length > limit) break;
      }
      return limit > 0 ? text.substring(0, limit) : text;
    }
    if (ext === "zip") {
      const JSZip = (await import("jszip")).default;
      const zip = await JSZip.loadAsync(buffer);
      const fileList = Object.keys(zip.files)
        .filter((k) => !zip.files[k].dir)
        .join("\n");
      const text = `ZIP 파일 목록:\n${fileList}`;
      return limit > 0 ? text.substring(0, limit) : text;
    }
  } catch (err) {
    console.error(`[EXTRACT_ERROR] ${ext}:`, err);
  }
  return null;
}

/** Gemini로 파일 분析 → {summary, tags, folder, status} */
export async function analyzeWithGemini(
  fileName: string,
  ext: string,
  content: string | null,
  existingFolders?: string[]
): Promise<{ summary: string; tags: string; folder: string; status: string }> {
  if (!content) {
    return {
      summary: "",
      tags: "",
      folder: inferFolderFromFilename(fileName, ext),
      status: "SKIPPED",
    };
  }

  // 기존 폴더 힌트 (최대 40개, 미분류 제외)
  const folderHint =
    existingFolders && existingFolders.length > 0
      ? `\n기존 폴더 목록 (가능하면 이 중에서 선택):\n${existingFolders
          .filter((f) => f !== "미분류")
          .slice(0, 40)
          .join(", ")}\n`
      : "";

  const prompt = `다음 파일을 분析해서 한국어로 요약, 태그, 폴더를 JSON으로 반환해줘.

파일명: ${fileName}
내용:
${content}
${folderHint}
폴더 규칙:
- "상위/하위" 2단계 계층 구조 (예: 보안/웹보안, 개발/Python, 문서/보고서, 학습/강의자료)
- 기존 폴더 목록과 유사한 내용이면 반드시 기존 폴더명을 그대로 사용
- 공백, 언더스코어 없이 붙여쓰기 (예: 웹보안 O, 웹 보안 X, 웹_보안 X)
- 한국어 우선, 단 CTF, AWS, ISMS-P, Python, SQL 등 고유명사는 영문 그대로

반드시 아래 JSON 형식으로만 응답해줘 (마크다운 없이 순수 JSON):
{"summary": "한국어 요약 2-3문장", "tags": "태그1,태그2,태그3,태그4,태그5", "folder": "상위/하위"}`;

  try {
    const raw = await callAI(prompt);
    const cleaned = raw.replace(/```json\n?|\n?```/g, "").trim();

    let parsed: { summary: string; tags: string; folder?: string };
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      const summaryMatch = cleaned.match(/"summary"\s*:\s*"([^"]+)"/);
      const tagsMatch = cleaned.match(/"tags"\s*:\s*"([^"]+)"/);
      const folderMatch = cleaned.match(/"folder"\s*:\s*"([^"]+)"/);
      parsed = {
        summary: summaryMatch?.[1] || "",
        tags: tagsMatch?.[1] || "",
        folder: folderMatch?.[1] || "",
      };
    }

    return {
      summary: parsed.summary || "",
      tags: parsed.tags || "",
      folder: normalizeFolder(parsed.folder || inferFolderFromFilename(fileName, ext)),
      status: "DONE",
    };
  } catch (err) {
    console.error("[GEMINI_ARCHIVE_ERROR]", err);
    return {
      summary: "",
      tags: "",
      folder: inferFolderFromFilename(fileName, ext),
      status: "FAILED",
    };
  }
}
