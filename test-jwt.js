import jwtDiag from './jwt-diagnostic-helper.js';

export default async function handler(req, res) {
  const result = await jwtDiag.run();
  res.json(result);
}