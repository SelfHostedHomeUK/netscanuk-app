require('dotenv').config();
const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3003;

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';
const GVM_USER = process.env.GVM_USER || 'admin';
const GVM_PASS = process.env.GVM_PASS || 'admin';

const CONTAINER = 'greenbone-community-edition-gvmd-1';
const SOCKET = '/run/gvmd/gvmd.sock';

// Known IDs from setup
const CONFIG_ID   = 'daba56c8-73ec-11df-a475-002264764cea'; // Full and fast
const SCANNER_ID  = '08b69003-5fc2-4037-a479-93b440211c73'; // OpenVAS Default
const PORTLIST_ID = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'; // All IANA TCP

app.use(express.json());
app.use(express.static('public'));

// Run a GMP XML command inside the gvmd container
async function gmp(xml) {
  const cmd = `docker exec --user gvmd ${CONTAINER} gvm-cli --gmp-username ${GVM_USER} --gmp-password ${GVM_PASS} socket --socketpath ${SOCKET} --xml '${xml}'`;
  const { stdout } = await execAsync(cmd);
  return stdout;
}

// Parse a single attribute value from XML string
function parseAttr(xml, tag, attr) {
  const re = new RegExp(`<${tag}[^>]*${attr}="([^"]+)"`);
  const m = xml.match(re);
  return m ? m[1] : null;
}

// Parse text content of a tag
function parseText(xml, tag) {
  const re = new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`);
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

// Create a scan target
async function createTarget(hosts) {
  const name = `netscan-${Date.now()}`;
  const xml = `<create_target><name>${name}</name><hosts>${hosts}</hosts><port_list id="${PORTLIST_ID}"/><alive_tests>Consider Alive</alive_tests></create_target>`;
  const res = await gmp(xml);
  const id = parseAttr(res, 'create_target_response', 'id');
  if (!id) throw new Error('Failed to create target: ' + res);
  return id;
}

// Create a scan task
async function createTask(targetId) {
  const name = `netscan-${Date.now()}`;
  const xml = `<create_task><name>${name}</name><config id="${CONFIG_ID}"/><target id="${targetId}"/><scanner id="${SCANNER_ID}"/></create_task>`;
  const res = await gmp(xml);
  const id = parseAttr(res, 'create_task_response', 'id');
  if (!id) throw new Error('Failed to create task: ' + res);
  return id;
}

// Start a task
async function startTask(taskId) {
  const res = await gmp(`<start_task task_id="${taskId}"/>`);
  const reportId = parseText(res, 'report_id');
  if (!reportId) throw new Error('Failed to start task: ' + res);
  return reportId;
}

// Get task status
async function getTaskStatus(taskId) {
  const res = await gmp(`<get_tasks task_id="${taskId}"/>`);
  const statusMatch = res.match(/<status>([^<]+)<\/status>/);
  const progressMatch = res.match(/<progress>([^<]+)<\/progress>/);
  return {
    status: statusMatch ? statusMatch[1] : 'Unknown',
    progress: progressMatch ? parseInt(progressMatch[1]) : 0,
  };
}

// Get report results
async function getReport(reportId) {
  const res = await gmp(`<get_results report_id="${reportId}" filter="min_qod=0 rows=100"/>`);
  return res;
}

// Parse results from XML report
function parseResults(xml) {
  const results = [];
  const resultMatches = xml.matchAll(/<result id="[^"]*">([\s\S]*?)<\/result>/g);
  for (const match of resultMatches) {
    const block = match[1];
    const name = parseText(block, 'name') || 'Unknown';
    const hostMatch = block.match(/<host>([\s\S]*?)<\/host>/);
    const host = hostMatch ? hostMatch[1].replace(/<[^>]+>/g, '').trim() : 'Unknown';
    const port = parseText(block, 'port') || 'N/A';
    const severity = parseText(block, 'severity') || '0';
    const descMatch = block.match(/<description>([\s\S]*?)<\/description>/);
    const description = descMatch ? descMatch[1].trim().substring(0, 500) : '';
    const solMatch = block.match(/<solution[^>]*>([\s\S]*?)<\/solution>/);
    const solution = solMatch ? solMatch[1].replace(/<[^>]+>/g, '').trim().substring(0, 300) : '';
    results.push({ host, port, severity, name, description, solution });
  }
  return results;
}

// Routes
app.get('/about', (req, res) => res.sendFile('about.html', { root: 'public' }));
app.get('/privacy', (req, res) => res.sendFile('privacy.html', { root: 'public' }));

// Start scan
app.post('/api/scan/start', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target IP or range required.' });

  try {
    const targetId = await createTarget(target);
    const taskId = await createTask(targetId);
    const reportId = await startTask(taskId);
    res.json({ taskId, reportId, message: 'Scan started.' });
  } catch (err) {
    console.error('Scan start error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Poll scan status
app.get('/api/status/:taskId', async (req, res) => {
  try {
    const status = await getTaskStatus(req.params.taskId);
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get and analyse results
app.post('/api/analyse', async (req, res) => {
  const { reportId } = req.body;
  if (!reportId) return res.status(400).json({ error: 'Report ID required.' });

  try {
    const xml = await getReport(reportId);
    const results = parseResults(xml);

    if (!results.length) {
      return res.json({
        executive: 'No significant vulnerabilities were detected on this network.',
        technical: 'The scan completed without finding vulnerabilities above the minimum quality of detection threshold.',
        attackPath: 'No clear attack path identified.',
        remediation: 'Continue regular scanning to monitor for changes.',
        nextAction: 'Schedule a follow-up scan in 30 days.',
        resultCount: 0
      });
    }

    // Sort by severity descending
    results.sort((a, b) => parseFloat(b.severity) - parseFloat(a.severity));

    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 8192,
      messages: [{
        role: 'user',
        content: `You are a senior network security analyst with 20 years of experience in enterprise IT security. You have received OpenVAS vulnerability scan results for a network.

Analyse these results and respond ONLY with a JSON object in this exact format, no preamble, no markdown:
{
  "executive": "2-3 sentences in plain English for a non-technical board audience — overall risk level and what it means for the business",
  "technical": "Prioritised technical breakdown grouped by severity (Critical/High/Medium/Low). For each significant finding explain what it is, why it matters, and the attack vector. Use clear paragraphs.",
  "attackPath": "The most likely attack path an adversary would take to compromise this network based on the findings. Be specific.",
  "remediation": "Prioritised remediation actions in order of importance. Include effort estimate: Quick Win / Medium Effort / Significant Effort for each.",
  "nextAction": "The single most important thing to fix right now, in one sentence."
}

Scan results (${results.length} findings):
${JSON.stringify(results.slice(0, 60), null, 2)}`
      }]
    });

    const text = message.content[0].text;
    let parsed;
    try {
      const clean = text.replace(/```json|```/g, '').trim();
      parsed = JSON.parse(clean);
    } catch {
      parsed = {
        executive: text,
        technical: '',
        attackPath: '',
        remediation: '',
        nextAction: '',
      };
    }

    res.json({ ...parsed, resultCount: results.length });

  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// Generate remediation script
app.post('/api/remediation', async (req, res) => {
  const { reportId } = req.body;
  if (!reportId) return res.status(400).json({ error: 'Report ID required.' });

  try {
    const xml = await gmp(`<get_results report_id="${reportId}" filter="min_qod=0 rows=100"/>`);
    const results = parseResults(xml);

    if (!results.length) {
      return res.json({ script: '#!/bin/bash\n# No significant findings to remediate.\necho "No remediation required."' });
    }

    results.sort((a, b) => parseFloat(b.severity) - parseFloat(a.severity));

    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 4096,
      messages: [{
        role: 'user',
        content: `You are a senior Linux security engineer. Based on these OpenVAS vulnerability scan results, generate a bash remediation script.

Rules:
- Output ONLY a valid bash script, no preamble, no markdown, no backticks
- Start with #!/bin/bash
- Include a clear comment header with date, target info, and a WARNING that the script should be reviewed before running
- Add a comment before each command explaining what it does and why
- Group commands by severity: CRITICAL/HIGH first, then MEDIUM, then LOW
- Only include commands that are safe, non-destructive, and commonly available on Ubuntu/Debian
- For each fix include a verification command commented out with # VERIFY:
- End with an echo summary of what was done
- If a fix requires manual intervention, add a comment explaining what to do instead of a command

Scan results (${results.length} findings):
${JSON.stringify(results.slice(0, 60), null, 2)}`
      }]
    });

    const script = message.content[0].text.replace(/\`\`\`bash|\`\`\`/g, '').trim();
    res.json({ script });

  } catch (err) {
    console.error('Remediation error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Netscan running on port ${PORT}`));
