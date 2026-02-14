import { CsvQuizRow } from "@/types/archive";

export function parseQuizCsv(csvString: string): { questions: CsvQuizRow[] } {
  const lines = csvString.trim().split('\n');
  const questions: CsvQuizRow[] = [];

  // Skip header row if it exists
  const startIndex = lines[0]?.toLowerCase().includes('question') ? 1 : 0;

  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Simple CSV parsing (handles basic cases)
    const parts = line.split(',').map(p => p.trim().replace(/^"|"$/g, ''));

    if (parts.length >= 2) {
      questions.push({
        question: parts[0],
        answer: parts[1],
        hint: parts[2] || undefined,
      });
    }
  }

  return { questions };
}
