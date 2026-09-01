/**
 * Hand-written line parser for schema.prisma files.
 *
 * Extracts models, fields, optional/list modifiers, attributes (@id, @unique,
 * @relation, @@map), and detects owner fields. Does not depend on @prisma/internals.
 *
 * @see context.md §6.5
 */

import * as fs from 'node:fs';
import { ScanConfigError } from '../core/errors.js';

export interface RelationInfo {
  relationField: string;
  fields: string[];
  references: string[];
  name?: string | undefined;
  targetModel: string;
}

export interface PrismaField {
  name: string;
  type: string;
  isOptional: boolean;
  isList: boolean;
  isId: boolean;
  isUnique: boolean;
  attributes: string[];
  relation?: {
    fields: string[];
    references: string[];
    name?: string | undefined;
  } | undefined;
}

export interface PrismaModel {
  name: string;
  tableName: string;
  fields: Map<string, PrismaField>;
  idFields: string[];
  relations: Map<string, RelationInfo>;
  ownerFields: string[];
}

export type PrismaSchemaResult = Map<string, PrismaModel>;

export const DEFAULT_OWNER_FIELDS = [
  'authorId',
  'userId',
  'ownerId',
  'tenantId',
  'createdById',
];

/**
 * Strip comments (// or ///) from a line, respecting quoted string literals.
 */
export function stripComments(line: string): string {
  let inDoubleQuote = false;
  let inSingleQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : '';

    if (ch === '"' && prev !== '\\' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
    } else if (ch === "'" && prev !== '\\' && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
    } else if (!inDoubleQuote && !inSingleQuote) {
      if (ch === '/' && i + 1 < line.length && line[i + 1] === '/') {
        return line.slice(0, i).trimEnd();
      }
    }
  }

  return line;
}

/**
 * Parse an attribute string like `@relation(fields: [authorId], references: [id])`
 */
function parseRelationAttribute(attrText: string): {
  fields: string[];
  references: string[];
  name?: string | undefined;
} {
  const fields: string[] = [];
  const references: string[] = [];
  let name: string | undefined;

  // Extract fields: [...]
  const fieldsMatch = /fields\s*:\s*\[([^\]]*)\]/.exec(attrText);
  if (fieldsMatch && fieldsMatch[1] !== undefined) {
    fields.push(
      ...fieldsMatch[1]
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    );
  }

  // Extract references: [...]
  const refMatch = /references\s*:\s*\[([^\]]*)\]/.exec(attrText);
  if (refMatch && refMatch[1] !== undefined) {
    references.push(
      ...refMatch[1]
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    );
  }

  // Extract name: "..." or first string literal before named arguments
  const nameMatch = /@relation\(\s*(?:name\s*:\s*)?"([^"]+)"/.exec(attrText);
  if (nameMatch && nameMatch[1] !== undefined) {
    name = nameMatch[1];
  }

  return { fields, references, name };
}

/**
 * Split a field line into field name, type, and attribute tokens.
 */
function parseFieldLine(line: string): {
  fieldName: string;
  rawType: string;
  attributes: string[];
} {
  const trimmed = line.trim();
  const tokens: string[] = [];
  let current = '';
  let inParen = 0;
  let inBracket = 0;
  let inQuote = false;

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (ch === undefined) continue;
    const prev = i > 0 ? (trimmed[i - 1] ?? '') : '';

    if (ch === '"' && prev !== '\\') {
      inQuote = !inQuote;
      current += ch;
    } else if (inQuote) {
      current += ch;
    } else if (ch === '(') {
      inParen++;
      current += ch;
    } else if (ch === ')') {
      inParen--;
      current += ch;
    } else if (ch === '[') {
      inBracket++;
      current += ch;
    } else if (ch === ']') {
      inBracket--;
      current += ch;
    } else if (/\s/.test(ch) && inParen === 0 && inBracket === 0) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  const fieldName = tokens[0] ?? '';
  const rawType = tokens[1] ?? '';
  const attributes = tokens.slice(2);

  return { fieldName, rawType, attributes };
}

interface RawModelBlock {
  name: string;
  startLine: number;
  tableName: string;
  idFields: string[];
  fieldLines: Array<{ line: string; lineNumber: number }>;
}

/**
 * Parse schema.prisma content into a map of PrismaModel definitions.
 *
 * @throws {ScanConfigError} with line number on malformed schema input
 */
export function parsePrismaSchema(
  content: string,
  options?: { filePath?: string | undefined; ownerFields?: string[] | undefined },
): PrismaSchemaResult {
  const filePath = options?.filePath ?? 'schema.prisma';
  const ownerFieldsList = options?.ownerFields ?? DEFAULT_OWNER_FIELDS;

  const lines = content.split('\n');
  const models = new Map<string, PrismaModel>();

  let currentBlock: RawModelBlock | null = null;
  let inOtherBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const rawLine = lines[i] ?? '';
    const cleanLine = stripComments(rawLine).trim();

    if (cleanLine.length === 0) continue;

    // Check if entering a non-model block (datasource, generator, enum)
    if (!currentBlock) {
      const otherMatch = /^(datasource|generator|enum)\s+[A-Za-z0-9_]+\s*\{/.exec(cleanLine);
      if (otherMatch) {
        inOtherBlock = true;
        continue;
      }

      if (inOtherBlock) {
        if (cleanLine.includes('}')) {
          inOtherBlock = false;
        }
        continue;
      }

      // Check model start
      const modelMatch = /^model\s+([A-Za-z0-9_]+)\s*\{?/.exec(cleanLine);
      if (modelMatch && modelMatch[1]) {
        currentBlock = {
          name: modelMatch[1],
          startLine: lineNumber,
          tableName: modelMatch[1],
          idFields: [],
          fieldLines: [],
        };
        continue;
      }

      // Any unexpected token outside of model or supported block
      if (cleanLine.includes('{') || cleanLine.includes('}')) {
        throw new ScanConfigError(`Unexpected token outside model block: '${cleanLine}'`, {
          filePath,
          lineNumber,
        });
      }

      continue;
    }

    // Inside a model block
    if (cleanLine === '}' || cleanLine.startsWith('}')) {
      // Model block completed, process fields
      const model = processModelBlock(currentBlock, ownerFieldsList, filePath);
      models.set(model.name, model);
      currentBlock = null;
      continue;
    }

    // Model-level attributes
    if (cleanLine.startsWith('@@')) {
      // @@map("table_name")
      const mapMatch = /@@map\("([^"]+)"\)/.exec(cleanLine);
      if (mapMatch && mapMatch[1]) {
        currentBlock.tableName = mapMatch[1];
        continue;
      }

      // @@id([field1, field2])
      const idMatch = /@@id\(\[([^\]]+)\]\)/.exec(cleanLine);
      if (idMatch && idMatch[1]) {
        const ids = idMatch[1]
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s.length > 0);
        currentBlock.idFields.push(...ids);
        continue;
      }

      // Other model attributes (@@unique, @@index) are valid and ignored for now
      continue;
    }

    // Field line
    currentBlock.fieldLines.push({ line: cleanLine, lineNumber });
  }

  // If EOF was reached while still in a model block
  if (currentBlock) {
    throw new ScanConfigError(
      `Unclosed model '${currentBlock.name}' in Prisma schema`,
      {
        filePath,
        lineNumber: currentBlock.startLine,
      },
    );
  }

  return models;
}

/**
 * Process raw lines inside a model block into a structured PrismaModel.
 */
function processModelBlock(
  raw: RawModelBlock,
  ownerFieldsList: string[],
  filePath: string,
): PrismaModel {
  const fields = new Map<string, PrismaField>();
  const relations = new Map<string, RelationInfo>();
  const idFields = [...raw.idFields];

  for (const { line, lineNumber } of raw.fieldLines) {
    const { fieldName, rawType, attributes } = parseFieldLine(line);

    if (!fieldName || !rawType) {
      throw new ScanConfigError(
        `Invalid field definition in model '${raw.name}': '${line}'`,
        {
          filePath,
          lineNumber,
        },
      );
    }

    let type = rawType;
    let isOptional = false;
    let isList = false;

    if (type.endsWith('?')) {
      isOptional = true;
      type = type.slice(0, -1);
    } else if (type.endsWith('[]')) {
      isList = true;
      type = type.slice(0, -2);
    }

    const isId = attributes.some((a) => a === '@id' || a.startsWith('@id('));
    if (isId && !idFields.includes(fieldName)) {
      idFields.push(fieldName);
    }

    const isUnique = attributes.some(
      (a) => a === '@unique' || a.startsWith('@unique('),
    );

    // Relation attribute
    let relation: PrismaField['relation'];
    const relationAttr = attributes.find((a) => a.startsWith('@relation'));
    if (relationAttr) {
      const parsedRel = parseRelationAttribute(relationAttr);
      relation = parsedRel;
      relations.set(fieldName, {
        relationField: fieldName,
        fields: parsedRel.fields,
        references: parsedRel.references,
        name: parsedRel.name,
        targetModel: type,
      });
    }

    fields.set(fieldName, {
      name: fieldName,
      type,
      isOptional,
      isList,
      isId,
      isUnique,
      attributes,
      relation,
    });
  }

  // Detect owner fields:
  // name ∈ ownerFieldsList AND (appears in a @relation(fields:[...]) OR ends with 'Id' scalar)
  const ownerFields: string[] = [];
  const relatedFieldNames = new Set<string>();
  for (const rel of relations.values()) {
    for (const f of rel.fields) {
      relatedFieldNames.add(f);
    }
  }

  for (const field of fields.values()) {
    if (ownerFieldsList.includes(field.name)) {
      const inRelation = relatedFieldNames.has(field.name);
      const isIdScalar = field.name.endsWith('Id') && !field.isList;
      if (inRelation || isIdScalar) {
        ownerFields.push(field.name);
      }
    }
  }

  return {
    name: raw.name,
    tableName: raw.tableName,
    fields,
    idFields,
    relations,
    ownerFields,
  };
}

/**
 * Load and parse a schema.prisma file from disk.
 *
 * @throws {ScanConfigError} if file cannot be read or parsed
 */
export function loadPrismaSchema(
  filePath: string,
  ownerFields?: string[],
): PrismaSchemaResult {
  if (!fs.existsSync(filePath)) {
    throw new ScanConfigError(`Prisma schema file not found: '${filePath}'`, {
      filePath,
    });
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return parsePrismaSchema(content, { filePath, ownerFields });
  } catch (err) {
    if (err instanceof ScanConfigError) {
      throw err;
    }
    throw new ScanConfigError(
      `Failed to read Prisma schema '${filePath}': ${err instanceof Error ? err.message : String(err)}`,
      { filePath, cause: err },
    );
  }
}
