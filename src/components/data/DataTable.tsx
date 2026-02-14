"use client";

import { Button } from "@/components/ui/button";
import { Edit, Trash2 } from "lucide-react";

interface DataTableProps {
  columns: string[];
  data: Record<string, unknown>[];
  onEdit?: (index: number) => void;
  onDelete?: (index: number) => void;
}

export function DataTable({ columns, data, onEdit, onDelete }: DataTableProps) {
  if (data.length === 0) {
    return <p className="text-center text-muted-foreground py-8">레코드가 없습니다</p>;
  }

  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            {columns.map((col) => (
              <th key={col} className="text-left p-3 font-medium">{col}</th>
            ))}
            {(onEdit || onDelete) && <th className="p-3 w-20">작업</th>}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} className="border-b hover:bg-muted/30">
              {columns.map((col) => (
                <td key={col} className="p-3 max-w-[200px] truncate">
                  {String(row[col] ?? "")}
                </td>
              ))}
              {(onEdit || onDelete) && (
                <td className="p-3">
                  <div className="flex gap-1">
                    {onEdit && (
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => onEdit(i)}>
                        <Edit className="h-3 w-3" />
                      </Button>
                    )}
                    {onDelete && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => onDelete(i)}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
