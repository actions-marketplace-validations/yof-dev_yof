/**
 * The small JSON-schema subset yof's MCP tools use, and a strict check of tool arguments against it. Unknown fields,
 * wrong types, too-long strings and numbers out of range are refused with a plain message; nothing is guessed.
 */
export interface StringProp { type: "string"; description: string; maxLength: number; enum?: readonly string[]; pattern?: string }
export interface IntegerProp { type: "integer"; description: string; minimum: number; maximum: number }
export interface BooleanProp { type: "boolean"; description: string }
export type Prop = StringProp | IntegerProp | BooleanProp;
export interface ToolSchema { type: "object"; properties: Record<string, Prop>; required?: readonly string[]; additionalProperties: false }

export class ArgsError extends Error {}

export function checkArgs(schema: ToolSchema, raw: unknown): Record<string, string | number | boolean> {
  const args = raw === undefined || raw === null ? {} : raw;
  if (typeof args !== "object" || Array.isArray(args)) throw new ArgsError("The arguments must be an object.");
  const out: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
    const p = schema.properties[k];
    if (!p) throw new ArgsError(`Unknown argument: ${k.slice(0, 40)}`);
    if (v === undefined || v === null) continue;
    if (p.type === "string") {
      if (typeof v !== "string") throw new ArgsError(`${k} must be text.`);
      if (v.length > p.maxLength) throw new ArgsError(`${k} is longer than ${p.maxLength} characters.`);
      if (p.enum && !p.enum.includes(v)) throw new ArgsError(`${k} must be one of: ${p.enum.join(", ")}`);
      if (p.pattern && !new RegExp(p.pattern).test(v)) throw new ArgsError(`${k} is not in the expected format.`);
      out[k] = v;
    } else if (p.type === "integer") {
      if (typeof v !== "number" || !Number.isInteger(v)) throw new ArgsError(`${k} must be a whole number.`);
      if (v < p.minimum || v > p.maximum) throw new ArgsError(`${k} must be between ${p.minimum} and ${p.maximum}.`);
      out[k] = v;
    } else {
      if (typeof v !== "boolean") throw new ArgsError(`${k} must be true or false.`);
      out[k] = v;
    }
  }
  for (const r of schema.required ?? []) if (!(r in out)) throw new ArgsError(`Missing argument: ${r}`);
  return out;
}
