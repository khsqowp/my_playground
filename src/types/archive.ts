export interface NoteData {
  id: string;
  title: string;
  content: string;
  visibility: "PUBLIC" | "PRIVATE" | "SHARED";
  categoryId: string | null;
  category: { id: string; name: string; slug: string; color: string | null } | null;
  tags: { tag: { id: string; name: string } }[];
  authorId: string;
  author: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
}

export interface NoteCreateInput {
  title: string;
  content: string;
  visibility?: "PUBLIC" | "PRIVATE" | "SHARED";
  categoryId?: string;
  tags?: string[];
}

export interface QuizSetData {
  id: string;
  title: string;
  description: string | null;
  visibility: "PUBLIC" | "PRIVATE" | "SHARED";
  questions: QuizQuestionData[];
  authorId: string;
  author: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
}

export interface QuizQuestionData {
  id: string;
  question: string;
  answer: string;
  hint: string | null;
  order: number;
}

export interface CsvQuizRow {
  question: string;
  answer: string;
  hint?: string;
}
