#!/usr/bin/env node
// Shim: dynamically import the built CLI to avoid ESM startup issues.
import('../dist/cli.js').catch((err) => {
  console.error('Failed to load trailguard CLI:', err.message);
  process.exit(2);
});
