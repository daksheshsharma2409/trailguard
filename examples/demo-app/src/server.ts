/**
 * Server entry point for Trailguard demo app.
 */

import { app } from './app.js';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Trailguard demo app listening on http://localhost:${String(PORT)}`);
});
