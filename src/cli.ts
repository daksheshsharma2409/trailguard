/**
 * trailguard CLI — thin wrapper over the library.
 *
 * This file must contain NO business logic.
 * All logic lives in library modules; this file only parses args and calls them.
 * The only permitted process.exit() calls in src/ are in this file.
 */

import { Command } from 'commander';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { scan } from './scan/index.js';
import { runVerifyCommand, type VerifyCommandOptions } from './cli/verify-command.js';
import type { Risk } from './core/types.js';

// Resolve package.json for the version string
const _require = createRequire(import.meta.url);
const _dirname = path.dirname(fileURLToPath(import.meta.url));
// package.json is one directory up from dist/ when built, or two up from src/
let pkg: { version: string } = { version: '0.0.0' };
try {
  // Works both from dist/ (built) and src/ (ts-node)
  pkg = _require(path.join(_dirname, '..', 'package.json')) as { version: string };
} catch {
  // fallback: try same dir
  try {
    pkg = _require(path.join(_dirname, 'package.json')) as { version: string };
  } catch {
    // ignore — version will be 0.0.0
  }
}

const program = new Command();

program
  .name('trailguard')
  .description('Declare, enforce, prove. Static RBAC scanner + tamper-evident audit log.')
  .version(pkg.version, '-v, --version', 'Print version and exit');

interface CliScanOptions {
  config?: string | undefined;
  format?: 'md' | 'json' | 'sarif' | undefined;
  out?: string | undefined;
  failOn?: Risk | 'none' | undefined;
  baseline?: string | undefined;
  updateBaseline?: boolean | undefined;
  verbose?: boolean | undefined;
}

// ── scan ──────────────────────────────────────────────────────────────────
program
  .command('scan [src]')
  .description('Scan Express source for unprotected routes and audit-coverage gaps')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--format <fmt>', 'Output format: md | json | sarif', 'md')
  .option('--out <file>', 'Write output to file instead of stdout')
  .option('--fail-on <level>', 'Exit 1 if any finding ≥ level: none | low | medium | high', 'high')
  .option('--baseline <file>', 'Suppress findings matching baseline file')
  .option('--update-baseline', 'Rewrite baseline from current findings')
  .option('--verbose', 'Verbose output')
  .action(async (src: string | undefined, opts: CliScanOptions) => {
    try {
      const result = await scan({
        src,
        config: opts.config,
        format: opts.format,
        out: opts.out,
        failOn: opts.failOn,
        baseline: opts.baseline,
        updateBaseline: opts.updateBaseline,
        verbose: opts.verbose,
      });

      if (!opts.out) {
        process.stdout.write(result.report);
      }

      process.exit(result.exitCode);
    } catch (err) {
      if (err instanceof Error) {
        console.error(`trailguard scan error: ${err.message}`);
        if (opts.verbose && err.stack) {
          console.error(err.stack);
        }
      } else {
        console.error('trailguard scan error:', String(err));
      }
      process.exit(2);
    }
  });

// ── verify ─────────────────────────────────────────────────────────────────
program
  .command('verify')
  .description('Verify the HMAC-chained audit log')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--checkpoints <file>', 'Path to checkpoints JSONL file')
  .option('--key-env <name>', 'Env var holding the HMAC key', 'TRAILGUARD_KEY')
  .option('--all', 'Collect all problems instead of stopping at first')
  .action(async (opts: VerifyCommandOptions) => {
    const outcome = await runVerifyCommand(opts);
    if (outcome.exitCode === 0 || outcome.exitCode === 1) {
      console.log(outcome.message);
    } else {
      console.error(outcome.message);
    }
    process.exit(outcome.exitCode);
  });

// ── drift ──────────────────────────────────────────────────────────────────
program
  .command('drift')
  .description('Compare declared matrix vs observed audit-log behavior')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--since <iso>', 'Only consider audit entries after this date')
  .action((_opts: unknown) => {
    // Implemented in T5.3
    console.error('trailguard drift: not yet implemented');
    process.exit(2);
  });

// ── ci ─────────────────────────────────────────────────────────────────────
program
  .command('ci')
  .description('Run scan → verify → drift; one summary, one exit code')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--no-db', 'Skip verify and drift (warn loudly)')
  .option('--format <fmt>', 'Output format for scan: md | json | sarif', 'md')
  .option('--out <file>', 'Write scan output to file')
  .option('--fail-on <level>', 'Threshold for scan findings', 'high')
  .option('--baseline <file>', 'Baseline file for scan')
  .action((_opts: unknown) => {
    // Implemented in T5.2
    console.error('trailguard ci: not yet implemented');
    process.exit(2);
  });

// ── export ─────────────────────────────────────────────────────────────────
program
  .command('export')
  .description('Export audit log entries as JSON or CSV')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--format <fmt>', 'json | csv', 'json')
  .option('--out <file>', 'Output file path (required for large exports)')
  .action((_opts: unknown) => {
    // Implemented in T5.3
    console.error('trailguard export: not yet implemented');
    process.exit(2);
  });

// ── checkpoint ─────────────────────────────────────────────────────────────
program
  .command('checkpoint')
  .description('Emit a signed checkpoint for the current chain head')
  .option('--config <path>', 'Path to trailguard.config.ts/js/json')
  .option('--key-env <name>', 'Env var holding the HMAC key', 'TRAILGUARD_KEY')
  .action((_opts: unknown) => {
    // Implemented in T5.3
    console.error('trailguard checkpoint: not yet implemented');
    process.exit(2);
  });

// ── init ───────────────────────────────────────────────────────────────────
program
  .command('init')
  .description('Write trailguard.config.ts and print the Prisma snippet')
  .option('--force', 'Overwrite existing config file')
  .action((_opts: unknown) => {
    // Implemented in T5.4
    console.error('trailguard init: not yet implemented');
    process.exit(2);
  });

program.parse(process.argv);
