require('dotenv').config();
const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { exec } = require('child_process');
const { promisify } = require('util');
const { parseStringPromise } = require('xml2js');

const execAsync = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3004;

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514';

app.use(express.json());
app.use(express.static('public'));

// In-memory scan store — taskId -> scan state
const scans = {};

// Generate a simple unique ID
function uid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// ── Run nmap scan ─────────────────────────────────────────────────────────────
async function runNmap(target) {
  // -sV  : service/version detection
  // -sC  : default NSE scripts (covers common misconfigs, SSL, HTTP headers etc)
  // -O   : OS detection
  // -p-  : all 65535 ports — use top 1000 for speed: remove -p- and add --top-ports 1000
  // --script: additional targeted scripts
  // -oX -: output XML to stdout
  // Timeout: 5 minutes max per host
  const nmapArgs = [
    '-sV',
    '-sC',
    '--script=banner,http-methods,http-headers,http-title,ssl-cert,ssl-enum-ciphers,ssh-auth-methods,ftp-anon,smtp-open-relay,dns-recursion,snmp-info,http-robots.txt,http-auth-finder',
    '--top-ports', '1000',
    '--host-timeout', '5m',
    '--open',
    '-oX', '-',
    target
  ].join(' ');

  const cmd = `nmap ${nmapArgs}`;
  const { stdout } = await execAsync(cmd, { timeout: 360000 }); // 6 min hard timeout
  return stdout;
}

// ── Parse nmap XML into findings ──────────────────────────────────────────────
async function parseNmapXml(xml) {
  const result = await parseStringPromise(xml, { explicitArray: false });
  const findings = [];

  const nmaprun = result.nmaprun;
  if (!nmaprun || !nmaprun.host) return findings;

  const hosts = Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host];

  for (const host of hosts) {
    const ip = host.address?.$ ? host.address.$.addr :
               (Array.isArray(host.address) ? host.address.find(a => a.$.addrtype === 'ipv4')?.$.addr : 'unknown');

    const hostname = host.hostnames?.hostname?.$.name || ip;

    if (!host.ports?.port) continue;
    const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];

    for (const port of ports) {
      const portNum = port.$.portid;
      const protocol = port.$.protocol;
      const state = port.state?.$.state;

      if (state !== 'open') continue;

      const service = port.service?.$ || {};
      const serviceName = service.name || 'unknown';
      const serviceProduct = service.product || '';
      const serviceVersion = service.version || '';
      const serviceExtra = service.extrainfo || '';

      // Collect script output
      const scriptResults = [];
      if (port.script) {
        const scripts = Array.isArray(port.script) ? port.script : [port.script];
        for (const script of scripts) {
          scriptResults.push({
            id: script.$.id,
            output: script.$.output
          });
        }
      }

      findings.push({
        host: ip,
        hostname,
        port: portNum,
        protocol,
        service: serviceName,
        product: `${serviceProduct} ${serviceVersion} ${serviceExtra}`.trim(),
        scripts: scriptResults
      });
    }

    // OS detection
    if (host.os?.osmatch) {
      const osmatches = Array.isArray(host.os.osmatch) ? host.os.osmatch : [host.os.osmatch];
      const topOs = osmatches[0];
      if (topOs) {
        findings.push({
          host: ip,
          hostname,
          port: 'os-detection',
          protocol: 'general',
          service: 'OS Detection',
          product: `${topOs.$.name} (accuracy: ${topOs.$.accuracy}%)`,
          scripts: []
        });
      }
    }
  }

  return findings;
}

// ── Routes ────────────────────────────────────────────────────────────────────
app.get('/about', (req, res) => res.sendFile('about.html', { root: 'public' }));
app.get('/privacy', (req, res) => res.sendFile('privacy.html', { root: 'public' }));

// Start scan
app.post('/api/scan/start', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target IP or range required.' });

  const taskId = uid();
  const reportId = uid();

  scans[taskId] = {
    status: 'Running',
    progress: 0,
    reportId,
    target,
    findings: null,
    error: null,
    startTime: Date.now()
  };

  // Run scan asynchronously
  (async () => {
    try {
      scans[taskId].progress = 10;
      const xml = await runNmap(target);
      scans[taskId].progress = 80;
      const findings = await parseNmapXml(xml);
      scans[taskId].findings = findings;
      scans[taskId].progress = 100;
      scans[taskId].status = 'Done';
    } catch (err) {
      console.error('Scan error:', err.message);
      scans[taskId].status = 'Failed';
      scans[taskId].error = err.message;
    }
  })();

  res.json({ taskId, reportId, message: 'Scan started.' });
});

// Poll status
app.get('/api/status/:taskId', (req, res) => {
  const scan = scans[req.params.taskId];
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ status: scan.status, progress: scan.progress });
});

// Analyse results
app.post('/api/analyse', async (req, res) => {
  const { reportId } = req.body;
  if (!reportId) return res.status(400).json({ error: 'Report ID required.' });

  // Find scan by reportId
  const scan = Object.values(scans).find(s => s.reportId === reportId);
  if (!scan) return res.status(404).json({ error: 'Report not found.' });
  if (scan.status !== 'Done') return res.status(400).json({ error: 'Scan not complete.' });

  const findings = scan.findings || [];

  if (!findings.length) {
    return res.json({
      executive: 'No open ports or services were detected on the target.',
      technical: 'The scan completed without finding any open ports or running services.',
      attackPath: 'No attack surface identified.',
      remediation: 'Confirm the target is reachable and the correct IP was used.',
      nextAction: 'Verify connectivity and re-scan.',
      resultCount: 0
    });
  }

  try {
    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 8192,
      messages: [{
        role: 'user',
        content: `You are a senior home network security analyst. You have received nmap scan results for a home/self-hosted network.

The target is a home network device — a Raspberry Pi, home server, NAS, or similar. Focus on practical home network security risks, not enterprise concerns.

Key things to look for:
- Services exposed that shouldn't be (admin interfaces, databases, dev servers)
- Default credentials indicators
- Unencrypted services (HTTP instead of HTTPS, FTP, Telnet)
- Outdated software versions with known CVEs
- SSH configuration weaknesses
- Open ports that suggest accidental internet exposure
- Docker ports exposed on 0.0.0.0 unnecessarily
- Development mode indicators (Node.js, etc)
- SSL/TLS certificate issues

Analyse these results and respond ONLY with a JSON object in this exact format, no preamble, no markdown:
{
  "executive": "2-3 sentences in plain English — overall risk level and what it means for a home user",
  "technical": "Prioritised technical breakdown. For each significant finding explain what it is, why it matters for a home network, and what the risk is. Use clear paragraphs grouped by severity.",
  "attackPath": "The most likely way someone could abuse what was found. Keep it practical and home-network relevant.",
  "remediation": "Prioritised fixes in order of importance with effort estimates: Quick Win / Medium Effort / Significant Effort.",
  "nextAction": "The single most important thing to fix right now, in one sentence."
}

Scan results (${findings.length} open ports/services found):
${JSON.stringify(findings, null, 2)}`
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

    res.json({ ...parsed, resultCount: findings.length });

  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Generate remediation script
app.post('/api/remediation', async (req, res) => {
  const { reportId } = req.body;
  if (!reportId) return res.status(400).json({ error: 'Report ID required.' });

  const scan = Object.values(scans).find(s => s.reportId === reportId);
  if (!scan) return res.status(404).json({ error: 'Report not found.' });
  if (scan.status !== 'Done') return res.status(400).json({ error: 'Scan not complete.' });

  const findings = scan.findings || [];

  if (!findings.length) {
    return res.json({ script: '#!/bin/bash\n# No findings to remediate.\necho "No remediation required."' });
  }

  try {
    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 4096,
      messages: [{
        role: 'user',
        content: `You are a senior Linux security engineer working with home network/self-hosted setups.

Based on these nmap scan results, generate a bash remediation script for a home user running Ubuntu/Raspberry Pi OS.

Rules:
- Output ONLY a valid bash script, no preamble, no markdown, no backticks
- Start with #!/bin/bash
- Include a header with date and WARNING to review before running
- Add a comment before each command explaining what it does
- Group by severity: HIGH first, then MEDIUM, then LOW
- Only include safe, non-destructive commands
- Include # VERIFY: lines after each fix
- For Docker-specific fixes, include docker compose restart instructions
- End with an echo summary
- If fix requires manual intervention add a clear comment instead of a command

Scan results:
${JSON.stringify(findings, null, 2)}`
      }]
    });

    const script = message.content[0].text.replace(/```bash|```/g, '').trim();
    res.json({ script });

  } catch (err) {
    console.error('Remediation error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Netscan running on port ${PORT}`));
