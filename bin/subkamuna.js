#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const path = require('path');
const fs = require('fs').promises;
const Subfinder = require('../lib/subfinder');

const program = new Command();

// Banner Function
function showBanner() {
  console.log(chalk.white(`
 
  #####                      #    #                                    
 #     # #    # #####        #   #    ##   #    # #    # #    #   ##   
 #       #    # #    #       #  #    #  #  ##  ## #    # ##   #  #  #  
  #####  #    # #####  ##### ###    #    # # ## # #    # # #  # #    # 
       # #    # #    #       #  #   ###### #    # #    # #  # # ###### 
 #     # #    # #    #       #   #  #    # #    # #    # #   ## #    # 
  #####   ####  #####        #    # #    # #    #  ####  #    # #    # 
`));
}

showBanner();

program
  .name('subkamuna')
  .description('Subdomain Scanner with New Features')
  .version('1.0.0');

program
  .argument('[domain]', 'Single domain to scan')
  .option('-d, --domain <domain>', 'Single domain to scan')
  .option('-l, --list <file>', 'File containing list of domains')
  .option('-o, --output <file>', 'Output file for results')
  .option('-t, --threads <number>', 'Number of concurrent threads', '50')
  .option('-to, --timeout <seconds>', 'HTTP request timeout', '5')
  .option('--no-http', 'Skip HTTP probing')
  .option('--only-live', 'Show only live domains')
  .option('-v, --verbose', 'Verbose output')
  .option('-s, --silent', 'Silent mode (minimal output)')
  
  // New Features
  .option('--scan-files', 'Discover files (robots.txt, sitemap.xml, etc.)')
  .option('--scan-folders', 'Discover common folders and directories')
  .option('--depth <number>', 'Directory scan depth', '3')
  .option('--real-report', 'Generate detailed real-time HTML report')
  .option('--tech-detect', 'Detect technologies (CMS, frameworks, servers)')
  .option('--screenshot', 'Take screenshots of live domains')
  .option('--email-extract', 'Extract email addresses from pages')
  .option('--js-extract', 'Extract endpoints from JavaScript files')
  .option('--csv-export', 'Export results to CSV format')
  .option('--wordlist <file>', 'Custom wordlist for directory scanning')
  .parse(process.argv);

async function main() {
  const options = program.opts();
  let domains = [];
  
  // Collect domains
  if (options.list) {
    try {
      const content = await fs.readFile(options.list, 'utf8');
      domains = content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    } catch (error) {
      console.error(chalk.red(`[-] Error reading domain list: ${error.message}`));
      process.exit(1);
    }
  } else if (options.domain) {
    domains = [options.domain];
  } else if (program.args[0]) {
    domains = [program.args[0]];
  } else {
    console.error(chalk.red('[-] Error: Please provide a domain or domain list file'));
    program.help();
  }

  // Validate domains
  const validate = require('../utils/validate');
  const validDomains = domains.filter(domain => {
    if (!validate.isValidDomain(domain)) {
      if (options.verbose) {
        console.log(chalk.yellow(`[-]  Invalid domain: ${domain}`));
      }
      return false;
    }
    return true;
  });

  if (validDomains.length === 0) {
    console.error(chalk.red('[-] No valid domains provided'));
    process.exit(1);
  }

  // Initialize subfinder
  const subfinder = new Subfinder({
    threads: parseInt(options.threads),
    timeout: parseInt(options.timeout),
    httpProbe: options.http !== false,
    onlyLive: options.onlyLive || false,
    verbose: options.verbose || false,
    silent: options.silent || false,
    scanFiles: options.scanFiles || false,
    scanFolders: options.scanFolders || false,
    depth: parseInt(options.depth),
    techDetect: options.techDetect || false,
    screenshot: options.screenshot || false,
    emailExtract: options.emailExtract || false,
    jsExtract: options.jsExtract || false,
    wordlist: options.wordlist || null
  });

  // Setup output
  let outputStream = null;
  if (options.output) {
    const outputPath = path.resolve(options.output);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    outputStream = await fs.open(outputPath, 'w');
  }

  // Display scan configuration
  if (!options.silent) {
    console.log(chalk.white(`\n[T] Targets: ${validDomains.length} domain(s)`));
    console.log(chalk.white(`[+] Threads: ${options.threads}`));
    console.log(chalk.white(`[+] HTTP Probe: ${options.http !== false ? 'Enabled' : 'Disabled'}`));
    if (options.scanFiles) console.log(chalk.white(`[+] File Discovery: Enabled`));
    if (options.scanFolders) console.log(chalk.white(`[+] Folder Discovery: Enabled (Depth: ${options.depth})`));
    if (options.techDetect) console.log(chalk.white(`[+] Tech Detection: Enabled`));
    if (options.emailExtract) console.log(chalk.white(`[+] Email Extraction: Enabled`));
    if (options.realReport) console.log(chalk.white(`[+] Report: Enabled`));
    console.log(chalk.gray(`\n${'═'.repeat(55)}\n`));
  }

  // Process each domain
  const allResults = {};
  const startTime = Date.now();
  
  for (let i = 0; i < validDomains.length; i++) {
    const domain = validDomains[i];
    
    if (!options.silent && validDomains.length > 1) {
      console.log(chalk.white(`[${i + 1}/${validDomains.length}] Processing: ${domain}`));
    }

    try {
      const result = await subfinder.scan(domain, outputStream);
      allResults[domain] = result;
      
      if (!options.silent) {
        console.log(chalk.white(`\n[+] ${domain}: ${result.live.length} live / ${result.total} total subdomains`));
        
        // Display additional findings
        if (result.files && result.files.length > 0) {
          console.log(chalk.white(`[F] Found ${result.files.length} interesting files`));
        }
        if (result.folders && result.folders.length > 0) {
          console.log(chalk.white(`[F] Found ${result.folders.length} accessible folders`));
        }
        if (result.emails && result.emails.length > 0) {
          console.log(chalk.white(`[F] Found ${result.emails.length} email addresses`));
        }
        if (result.technologies && Object.keys(result.technologies).length > 0) {
          console.log(chalk.white(`[D] Detected ${Object.keys(result.technologies).length} technologies`));
        }
      }
    } catch (error) {
      console.error(chalk.red(`[-] Error scanning ${domain}: ${error.message}`));
    }
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);

  // Generate Real Report
  if (options.realReport && !options.silent) {
    await generateRealReport(allResults, totalTime, options);
  }

  // Export to CSV
  if (options.csvExport && !options.silent) {
    await exportToCSV(allResults);
  }

  // Final Summary
  if (!options.silent) {
    console.log(chalk.cyan('\n' + ''.repeat(55)));
    console.log(chalk.white.bold('[+] FINAL SCAN '));
    console.log(chalk.cyan(''.repeat(55)));
    
    let totalLive = 0;
    let totalSubs = 0;
    let totalFiles = 0;
    let totalFolders = 0;
    let totalEmails = 0;
    
    for (const [domain, result] of Object.entries(allResults)) {
      totalLive += result.live.length;
      totalSubs += result.total;
      totalFiles += result.files?.length || 0;
      totalFolders += result.folders?.length || 0;
      totalEmails += result.emails?.length || 0;
      console.log(chalk.white(`\n${domain}:`));
      console.log(chalk.white(`Subdomains: ${chalk.white(result.total)}`));
      console.log(chalk.white(`Live Services: ${chalk.white(result.live.length)}`));
      if (result.files?.length) console.log(chalk.white(`Files: ${chalk.white(result.files.length)}`));
      if (result.folders?.length) console.log(chalk.white(`Folders: ${chalk.white(result.folders.length)}`));
      if (result.emails?.length) console.log(chalk.white(`Emails: ${chalk.white(result.emails.length)}`));
    }
    console.log(chalk.cyan('\n' + ''.repeat(55)));
    console.log(chalk.white(`[-] Total Time: ${totalTime}s`));
    console.log(chalk.white(`[-] Total Subdomains: ${totalSubs}`));
    console.log(chalk.white(`[-] Total Live: ${totalLive}`));
    if (totalFiles > 0) console.log(chalk.white(`[-] Total Files: ${totalFiles}`));
    if (totalFolders > 0) console.log(chalk.white(`[-] Total Folders: ${totalFolders}`));
    if (totalEmails > 0) console.log(chalk.white(`[-] Total Emails: ${totalEmails}`));
    console.log(chalk.cyan(''.repeat(55) + '\n'));
  }

  if (outputStream) {
    await outputStream.close();
    if (!options.silent) {
      console.log(chalk.white(`[+] Results saved to: ${options.output}`));
    }
  }
}

// Generate Real HTML Report
async function generateRealReport(results, totalTime, options) {
  const reportDir = path.join(process.cwd(), 'reports');
  await fs.mkdir(reportDir, { recursive: true });
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = path.join(reportDir, `report_${timestamp}.html`);
  
  let htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubKamuna Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .stat-card h3 { font-size: 2em; color: #667eea; margin-bottom: 5px; }
        .stat-card p { color: #666; font-size: 0.9em; }
        .content { padding: 40px; }
        .domain-section {
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
        }
        .domain-header {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            font-weight: bold;
        }
        .domain-body {
            padding: 20px;
            display: none;
        }
        .domain-body.active { display: block; }
        .subdomain-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .subdomain-item {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .status-200 { color: #28a745; font-weight: bold; }
        .status-301, .status-302 { color: #ffc107; }
        .status-403, .status-404 { color: #dc3545; }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin: 2px;
        }
        .badge-live { background: #28a745; color: white; }
        .badge-file { background: #17a2b8; color: white; }
        .badge-folder { background: #ffc107; color: #333; }
        .badge-email { background: #dc3545; color: white; }
        .tech-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 10px;
        }
        .tech-item {
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
        }
        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover { background: #5a67d8; }
        @media (max-width: 768px) {
            .stats { grid-template-columns: 1fr; }
            .subdomain-list { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> SubKamuna Scan Report</h1>
            <p>Generated on ${new Date().toLocaleString()}</p>
            <p>Scan Duration: ${totalTime} seconds</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>${Object.keys(results).length}</h3>
                <p>Domains Scanned</p>
            </div>
            <div class="stat-card">
                <h3>${Object.values(results).reduce((sum, r) => sum + r.total, 0)}</h3>
                <p>Total Subdomains</p>
            </div>
            <div class="stat-card">
                <h3>${Object.values(results).reduce((sum, r) => sum + r.live.length, 0)}</h3>
                <p>Live Services</p>
            </div>
            <div class="stat-card">
                <h3>${Object.values(results).reduce((sum, r) => sum + (r.files?.length || 0), 0)}</h3>
                <p>Files Discovered</p>
            </div>
        </div>
        
        <div class="content">
            <button onclick="expandAll()">Expand All</button>
            <button onclick="collapseAll()">Collapse All</button>
            <button onclick="exportToJSON()">Export JSON</button>
            <button onclick="window.print()">Print Report</button>
            <br><br>`;
  
  for (const [domain, result] of Object.entries(results)) {
    htmlContent += `
            <div class="domain-section">
                <div class="domain-header" onclick="toggleDomain(this)">
                    [+] ${domain} - ${result.live.length} live / ${result.total} total
                </div>
                <div class="domain-body">
                    <h4>[-] Live Subdomains (${result.live.length})</h4>
                    <div class="subdomain-list">`;
    
    for (const live of result.live.slice(0, 50)) {
      const statusMatch = live.match(/\((\d+)\)/);
      const status = statusMatch ? statusMatch[1] : '';
      htmlContent += `<div class="subdomain-item">
                        <span class="status-${status}">${live}</span>
                      </div>`;
    }
    
    if (result.live.length > 50) {
      htmlContent += `<div class="subdomain-item">... and ${result.live.length - 50} more</div>`;
    }
    
    htmlContent += `</div>`;
    
    if (result.files?.length) {
      htmlContent += `<h4 style="margin-top: 20px;">[+] Interesting Files (${result.files.length})</h4>
                      <div class="subdomain-list">`;
      for (const file of result.files) {
        htmlContent += `<div class="subdomain-item"><span class="badge badge-file">FILE</span> ${file}</div>`;
      }
      htmlContent += `</div>`;
    }
    
    if (result.folders?.length) {
      htmlContent += `<h4 style="margin-top: 20px;">[+] Accessible Folders (${result.folders.length})</h4>
                      <div class="subdomain-list">`;
      for (const folder of result.folders) {
        htmlContent += `<div class="subdomain-item"><span class="badge badge-folder">DIR</span> ${folder}</div>`;
      }
      htmlContent += `</div>`;
    }
    
    if (result.emails?.length) {
      htmlContent += `<h4 style="margin-top: 20px;">[+] Email Addresses (${result.emails.length})</h4>
                      <div class="subdomain-list">`;
      for (const email of result.emails) {
        htmlContent += `<div class="subdomain-item"><span class="badge badge-email">EMAIL</span> ${email}</div>`;
      }
      htmlContent += `</div>`;
    }
    
    if (result.technologies && Object.keys(result.technologies).length > 0) {
      htmlContent += `<h4 style="margin-top: 20px;">🔧 Detected Technologies</h4>
                      <div class="tech-list">`;
      for (const [tech, version] of Object.entries(result.technologies)) {
        htmlContent += `<div class="tech-item">${tech}${version ? ` ${version}` : ''}</div>`;
      }
      htmlContent += `</div>`;
    }
    
    htmlContent += `
                </div>
            </div>`;
  }
  
  htmlContent += `
        </div>
        <div class="footer">
            <p>Generated by SubKamuna Ultimate Scanner v1.0</p>
            <p>Bug Bounty Ready | Recon Tool</p>
        </div>
    </div>
    
    <script>
        function toggleDomain(header) {
            const body = header.nextElementSibling;
            body.classList.toggle('active');
        }
        
        function expandAll() {
            document.querySelectorAll('.domain-body').forEach(body => {
                body.classList.add('active');
            });
        }
        
        function collapseAll() {
            document.querySelectorAll('.domain-body').forEach(body => {
                body.classList.remove('active');
            });
        }
        
        function exportToJSON() {
            const data = ${JSON.stringify(results, null, 2)};
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'subkamuna_report.json';
            a.click();
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>`;
  
  await fs.writeFile(reportFile, htmlContent);
  console.log(chalk.white(`\n[+] Report generated: ${reportFile}`));
}

// Export to CSV
async function exportToCSV(results) {
  const csvDir = path.join(process.cwd(), 'exports');
  await fs.mkdir(csvDir, { recursive: true });
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const csvFile = path.join(csvDir, `export_${timestamp}.csv`);
  
  let csvContent = 'Domain,Subdomain,Status,Type,URL\n';
  
  for (const [domain, result] of Object.entries(results)) {
    for (const live of result.live) {
      const urlMatch = live.match(/(https?:\/\/[^\s]+)/);
      const statusMatch = live.match(/\((\d+)\)/);
      csvContent += `"${domain}","${live}","${statusMatch ? statusMatch[1] : ''}","live","${urlMatch ? urlMatch[1] : ''}"\n`;
    }
    
    for (const file of result.files || []) {
      csvContent += `"${domain}","${file}","","file",""\n`;
    }
    
    for (const folder of result.folders || []) {
      csvContent += `"${domain}","${folder}","","folder",""\n`;
    }
    
    for (const email of result.emails || []) {
      csvContent += `"${domain}","${email}","","email",""\n`;
    }
  }
  
  await fs.writeFile(csvFile, csvContent);
  console.log(chalk.white(`[+] CSV Export saved: ${csvFile}`));
}

// Error handling
process.on('unhandledRejection', (error) => {
  console.error(chalk.red('[-] Unhandled error:'), error);
  process.exit(1);
});

main().catch(error => {
  console.error(chalk.red('[-] Fatal error:'), error);
  process.exit(1);
});