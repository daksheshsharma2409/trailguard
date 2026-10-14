/**
 * SARIF 2.1.0 reporter for Trailguard static analysis.
 *
 * Emits standard SARIF 2.1.0 JSON format for GitHub code scanning and SARIF-compliant tools.
 * Supports partialFingerprints and external suppressions (baseline).
 *
 * @see context.md §6.12, tasks.md T2.13, T5.5
 */

import type { ScanResult } from '../../core/types.js';
import { DEFAULT_RULES } from '../rules/index.js';

export interface SarifArtifactLocation {
  uri: string;
}

export interface SarifRegion {
  startLine: number;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region: SarifRegion;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifSuppression {
  kind: 'external' | 'inSource';
  status?: 'accepted' | 'underReview' | 'rejected';
  justification?: string;
}

export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints: Record<string, string>;
  suppressions?: SarifSuppression[];
}

export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri?: string;
      rules: SarifReportingDescriptor[];
    };
  };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

/**
 * Formats a scan result into a SARIF 2.1.0 JSON string.
 */
export function formatSarifReport(scanResult: ScanResult): string {
  const ruleMap = new Map(DEFAULT_RULES.map((r) => [r.id, r]));

  // Collect all unique rule IDs referenced by findings and default rules
  const allRuleIds = new Set<string>();
  for (const r of DEFAULT_RULES) {
    allRuleIds.add(r.id);
  }
  for (const f of scanResult.findings) {
    allRuleIds.add(f.ruleId);
  }

  const rules: SarifReportingDescriptor[] = Array.from(allRuleIds).map((id) => {
    const meta = ruleMap.get(id);
    const ruleTitle = meta !== undefined ? meta.title : id;
    const defaultLevel: 'error' | 'warning' | 'note' =
      meta !== undefined && meta.defaultRisk === 'high'
        ? 'error'
        : meta !== undefined && meta.defaultRisk === 'medium'
          ? 'warning'
          : 'note';

    return {
      id,
      name: id,
      shortDescription: { text: ruleTitle },
      fullDescription: { text: ruleTitle },
      defaultConfiguration: {
        level: defaultLevel,
      },
    };
  });

  const results: SarifResult[] = scanResult.findings.map((f) => {
    const level: 'error' | 'warning' | 'note' =
      f.risk === 'high' ? 'error' : f.risk === 'medium' ? 'warning' : 'note';

    const item: SarifResult = {
      ruleId: f.ruleId,
      level,
      message: { text: f.message },
      partialFingerprints: {
        primaryLocationLineHash: f.fingerprint,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: {
              startLine: Math.max(1, f.line),
            },
          },
        },
      ],
    };

    if (f.suppressed === true) {
      item.suppressions = [
        {
          kind: 'external',
          status: 'accepted',
          justification: 'Suppressed via baseline',
        },
      ];
    }

    return item;
  });

  const sarifLog: SarifLog = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'trailguard',
            version: scanResult.version,
            informationUri: 'https://github.com/daksheshsharma/trailguard',
            rules,
          },
        },
        results,
      },
    ],
  };

  return `${JSON.stringify(sarifLog, null, 2)}\n`;
}
