import type { Report, PolicyOptions, RuleInfo, Severity } from './core.js';
export * from './core.js';
export type Verdict = 'clean' | 'low-risk' | 'suspicious' | 'likely-phishing' | 'invalid';
export interface Signal { rule: string; message: string; evidence?: string; weight: number; }
export interface UrlAnalysis { url: string; host?: string | null; unicodeHost?: string; domain?: string | null; score: number; verdict: Verdict; signals: Signal[]; invalid?: boolean; }
export type BrandTable = Record<string, string[]>;
export interface CheckOptions extends PolicyOptions { protect?: string[]; trusted?: string[]; builtinBrands?: boolean; }
export declare const VERSION: string;
export declare const RULES: Record<string, RuleInfo>;
export declare const WEIGHTS: Record<string, number>;
export declare const BRANDS: BrandTable;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare function analyzeUrl(url: string, opts?: { brands?: BrandTable; protect?: string[]; trusted?: string[] }): UrlAnalysis;
export declare function extractUrls(text: string): string[];
export declare function registrableDomain(host: string): string;
export declare function skeleton(label: string): string;
export declare function distance(a: string, b: string): number;
export declare function brandTable(protect?: string[], opts?: { builtin?: boolean }): BrandTable;
export declare function collectUrls(inputs: string[]): { urls: Array<{ url: string; source?: string }>; errors: Array<{ source: string; error: string }> };
/** Score URLs (or files containing URLs) offline. */
export declare function check(inputs: string[], opts?: CheckOptions): Report;
export declare function formatTable(report: Report): string;
