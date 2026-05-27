import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Tailwind クラス名を安全にマージする shadcn/ui 標準ヘルパ。 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
