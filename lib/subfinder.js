const { exec } = require('child_process');
const util = require('util');
const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const cliProgress = require('cli-progress');
const pLimit = require('p-limit');
const dns = require('dns').promises;
const os = require('os');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const execPromise = util.promisify(exec);

class Subfinder {
  constructor(options = {}) {
    this.threads = options.threads || 50;
    this.timeout = options.timeout || 5;
    this.httpProbe = options.httpProbe !== false;
    this.onlyLive = options.onlyLive || false;
    this.verbose = options.verbose || false;
    this.silent = options.silent || false;
    this.scanFiles = options.scanFiles || false;
    this.scanFolders = options.scanFolders || false;
    this.depth = options.depth || 3;
    this.techDetect = options.techDetect || false;
    this.emailExtract = options.emailExtract || false;
    this.jsExtract = options.jsExtract || false;
    this.isWindows = os.platform() === 'win32';
    this.subfinderPath = null;
    this.cacheEnabled = options.cacheEnabled !== false;
    this.cacheFile = path.join(process.cwd(), '.subfinder_cache.json');
    this.cache = {};
  }

  async init() {
    // Load cache
    if (this.cacheEnabled) {
      try {
        const cacheData = await fs.readFile(this.cacheFile, 'utf8');
        this.cache = JSON.parse(cacheData);
      } catch (e) {}
    }
    
    // Find subfinder path
    this.subfinderPath = await this.findSubfinder();
  }

  async findSubfinder() {
    const possiblePaths = [
      'subfinder',
      'subfinder.exe',
      path.join(process.cwd(), 'subfinder.exe'),
      path.join(process.cwd(), 'bin', 'subfinder.exe'),
      path.join(process.cwd(), 'tools', 'subfinder.exe'),
      'C:\\Users\\menme\\go\\bin\\subfinder.exe',
      'C:\\Program Files\\subfinder\\subfinder.exe',
      '/usr/local/bin/subfinder',
      '/usr/bin/subfinder'
    ];
    
    for (const p of possiblePaths) {
      try {
        await execPromise(`${p} -version 2>nul`);
        if (!this.silent && this.verbose) {
          console.log(chalk.green(`Found subfinder at: ${p}`));
        }
        return p;
      } catch (e) {}
    }
    
    return null;
  }

  async scan(domain, outputStream = null) {
    await this.init();
    
    // Step 1: Get subdomains
    const subdomains = await this.getSubdomains(domain);
    
    if (!this.silent && this.verbose) {
      console.log(chalk.blue(`Found ${subdomains.length} subdomains for ${domain}`));
    }

    // Step 2: HTTP probing
    let liveResults = [];
    let files = [];
    let folders = [];
    let emails = [];
    let technologies = {};
    let jsEndpoints = [];
    
    if (this.httpProbe && subdomains.length > 0) {
      liveResults = await this.probeHTTP(subdomains, domain);
      
      if (liveResults.length > 0) {
        const liveUrls = liveResults.map(r => r.fullUrl);
        
        if (this.scanFiles) {
          files = await this.discoverFiles(liveUrls);
        }
        
        if (this.scanFolders) {
          folders = await this.discoverFolders(liveUrls);
        }
        
        if (this.emailExtract) {
          emails = await this.extractEmails(liveUrls);
        }
        
        if (this.techDetect) {
          technologies = await this.detectTechnologies(liveResults);
        }
        
        if (this.jsExtract) {
          jsEndpoints = await this.extractJSEndpoints(liveUrls);
        }
      }
    }

    // Step 3: Save results
    await this.saveResults(domain, subdomains, liveResults, {
      files, folders, emails, technologies, jsEndpoints
    }, outputStream);

    return {
      domain,
      total: subdomains.length,
      live: liveResults.map(r => r.displayUrl),
      liveDetailed: liveResults,
      all: subdomains,
      files,
      folders,
      emails,
      technologies,
      jsEndpoints
    };
  }

  async getSubdomains(domain) {
    // Check cache first
    const cacheKey = `subdomains_${domain}`;
    if (this.cacheEnabled && this.cache[cacheKey]) {
      const cached = this.cache[cacheKey];
      const cacheAge = Date.now() - cached.timestamp;
      if (cacheAge < 86400000) { // 24 hours cache
        if (!this.silent) {
          console.log(chalk.gray(` Using cached results for ${domain} (${Math.floor(cacheAge / 3600000)}h ago)`));
        }
        return cached.subdomains;
      }
    }
    
    let subdomains = [];
    
    // Try Subfinder first
    if (this.subfinderPath) {
      subdomains = await this.runSubfinder(domain);
    }
    
    // If Subfinder found nothing or not available, use DNS brute force
    if (subdomains.length === 0) {
      subdomains = await this.dnsBruteForce(domain);
    }
    
    // Add main domain
    if (!subdomains.includes(domain)) {
      subdomains.unshift(domain);
    }
    
    // Remove duplicates
    subdomains = [...new Set(subdomains)];
    
    // Save to cache
    if (this.cacheEnabled && subdomains.length > 0) {
      this.cache[cacheKey] = {
        timestamp: Date.now(),
        subdomains: subdomains
      };
      await fs.writeFile(this.cacheFile, JSON.stringify(this.cache, null, 2));
    }
    
    return subdomains;
  }

  async runSubfinder(domain) {
    const spinner = !this.silent ? ora(` Running subfinder on ${domain}...`).start() : null;
    
    try {
      const command = `${this.subfinderPath} -d ${domain} -silent -t ${this.threads} -timeout ${this.timeout}`;
      const { stdout, stderr } = await execPromise(command);
      
      const subdomains = stdout
        .split(/\r?\n/)
        .map(line => line.trim().toLowerCase())
        .filter(line => line && line.includes(domain));
      
      if (spinner) {
        spinner.succeed(`Subfinder found ${subdomains.length} subdomains`);
      }
      
      return subdomains;
      
    } catch (error) {
      if (spinner) {
        spinner.fail(`Subfinder failed: ${error.message}`);
      }
      return [];
    }
  }

  async dnsBruteForce(domain) {
    const spinner = !this.silent ? ora(` DNS brute forcing ${domain}...`).start() : null;
    
    // Comprehensive wordlist
    const wordlist = this.getWordlist();
    
    const subdomains = [];
    const limit = pLimit(this.threads);
    let foundCount = 0;
    
    const tasks = wordlist.map(sub => 
      limit(async () => {
        const hostname = `${sub}.${domain}`;
        try {
          await dns.lookup(hostname);
          subdomains.push(hostname);
          foundCount++;
          if (this.verbose && !this.silent) {
            console.log(chalk.green(`  ✓ ${hostname}`));
          }
        } catch (err) {}
      })
    );
    
    await Promise.all(tasks);
    
    if (spinner) {
      spinner.succeed(`DNS brute force found ${subdomains.length} subdomains`);
    }
    
    return subdomains;
  }

  getWordlist() {
    return [
      // Common
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
      'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
      'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
      'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
      'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
      'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
      'dashboard', 'portal', 'manage', 'start', 'info', 'app', 'apps', 'api', 'svn',
      'backup', 'git', 'crm', 'faq', 'help', 'status', 'live', 'stream', 'chat',
      'cloud', 'remote', 'exchange', 'owa', 'lync', 'sharepoint', 'vps', 'server',
      
      // Admin panels
      'administrator', 'admin-panel', 'admincp', 'controlpanel', 'manager', 'backend',
      'cms', 'wp-admin', 'joomla-admin', 'drupal-admin', 'magento-admin',
      
      // Development
      'staging', 'stage', 'test', 'testing', 'dev', 'development', 'sandbox', 'demo',
      'preprod', 'preproduction', 'uat', 'quality', 'qa', 'qc',
      
      // APIs
      'api', 'rest', 'graphql', 'socket', 'ws', 'wss', 'apiv1', 'apiv2', 'v1', 'v2', 'v3',
      'rest-api', 'json-api', 'xml-api', 'soap',
      
      // Services
      'mail', 'email', 'smtp', 'imap', 'pop3', 'exchange', 'outlook',
      'ftp', 'sftp', 'ssh', 'telnet', 'remote', 'terminal',
      'vpn', 'proxy', 'gateway', 'router', 'firewall', 'loadbalancer',
      
      // Monitoring
      'monitor', 'status', 'health', 'check', 'ping', 'uptime', 'metrics', 'grafana',
      'prometheus', 'datadog', 'newrelic', 'splunk', 'elk', 'kibana', 'logstash',
      
      // Storage
      'cdn', 'static', 'assets', 'res', 'img', 'video', 'audio', 'files', 'upload',
      'download', 'media', 'storage', 'db', 'database', 'sql', 'redis', 'memcached',
      'elasticsearch', 'mongodb', 'couchdb', 'dynamodb',
      
      // Security
      'security', 'auth', 'login', 'signin', 'oauth', 'sso', 'saml', 'ldap', 'radius',
      'cert', 'pki', 'ca', 'certs', 'ssl', 'tls',
      
      // Business
      'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing', 'invoice',
      'account', 'profile', 'user', 'users', 'customer', 'client', 'partner',
      'vendor', 'supplier', 'distributor',
      
      // Social
      'chat', 'talk', 'conference', 'meet', 'zoom', 'team', 'slack', 'discord',
      'forum', 'community', 'support', 'help', 'ticket',
      
      // Additional
      'logs', 'log', 'debug', 'trace', 'profile', 'perf', 'benchmark',
      'backup', 'archive', 'old', 'legacy', 'deprecated', 'archive', 'historical',
      'cdn', 'edge', 'fastly', 'cloudfront', 'cloudflare', 'akamai'
    ];
  }

  async probeHTTP(subdomains, parentDomain) {
    if (!this.silent) {
      console.log(chalk.blue(`\n Probing ${subdomains.length} subdomains...`));
    }
    
    const results = [];
    const limit = pLimit(this.threads);
    const progressBar = !this.silent ? new cliProgress.SingleBar({
      format: 'Progress |{bar}| {percentage}% | {value}/{total}',
      barCompleteChar: '\u2588',
      barIncompleteChar: '\u2591',
      hideCursor: true
    }, cliProgress.Presets.shades_classic) : null;
    
    if (progressBar) {
      progressBar.start(subdomains.length, 0);
    }
    
    let completed = 0;
    const tasks = subdomains.map(subdomain =>
      limit(async () => {
        const result = await this.checkHTTPDetailed(subdomain);
        if (result) {
          results.push(result);
        }
        completed++;
        if (progressBar) {
          progressBar.update(completed);
        }
      })
    );
    
    await Promise.all(tasks);
    
    if (progressBar) {
      progressBar.stop();
    }
    
    if (!this.silent) {
      console.log(chalk.green(` Found ${results.length} live services`));
    }
    
    return results;
  }

  async checkHTTPDetailed(subdomain) {
    const protocols = ['https', 'http'];
    
    for (const protocol of protocols) {
      const url = `${protocol}://${subdomain}`;
      const startTime = Date.now();
      
      try {
        const response = await axios.get(url, {
          timeout: this.timeout * 1000,
          maxRedirects: 5,
          validateStatus: status => status < 600,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubKamuna/4.0'
          }
        });
        
        const result = {
          subdomain: subdomain,
          url: url,
          fullUrl: url,
          displayUrl: `${url} (${response.status})`,
          statusCode: response.status,
          statusText: response.statusText,
          responseTime: Date.now() - startTime,
          server: response.headers['server'] || 'unknown',
          contentType: response.headers['content-type'] || 'unknown',
          contentLength: parseInt(response.headers['content-length']) || response.data.length,
          technologies: [],
          title: this.extractTitle(response.data),
          headers: response.headers
        };
        
        const coloredStatus = this.getStatusColor(response.status);
        
        if (this.verbose && !this.silent) {
          console.log(`${coloredStatus} ${url} [${result.responseTime}ms] [${result.server}]`);
        } else if (!this.silent) {
          const statusIcon = response.status >= 200 && response.status < 300 ? '✓' : '●';
          console.log(chalk.gray(`${statusIcon} ${url} [${response.status}]`));
        }
        
        return result;
        
      } catch (error) {
        if (this.verbose && !this.silent && error.code !== 'ECONNREFUSED') {
          console.log(chalk.gray(`✗ ${url} - ${error.code || error.message}`));
        }
      }
    }
    
    return null;
  }

  extractTitle(html) {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim().substring(0, 100) : '';
  }

  async discoverFiles(urls) {
    const interestingFiles = [
      'robots.txt', 'sitemap.xml', 'sitemap.xml.gz', 'security.txt',
      '.git/config', '.env', '.env.backup', '.env.production', '.env.local',
      '.htaccess', '.htpasswd', 'crossdomain.xml', 'clientaccesspolicy.xml',
      'package.json', 'composer.json', 'yarn.lock', 'package-lock.json',
      'wp-config.php', 'wp-config.php.bak', 'wp-config.old',
      'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE', 'LICENSE.txt',
      'phpinfo.php', 'info.php', 'test.php', 'debug.php', 'admin.php',
      'backup.zip', 'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
      'web.config', 'app.config', 'config.json', 'config.yml', 'config.yaml',
      '.dockerignore', 'Dockerfile', 'docker-compose.yml',
      '.travis.yml', '.gitlab-ci.yml', 'Jenkinsfile'
    ];
    
    const foundFiles = [];
    const limit = pLimit(this.threads);
    
    const tasks = [];
    for (const url of urls.slice(0, 50)) { // Limit to 50 URLs
      for (const file of interestingFiles.slice(0, 30)) { // Limit files
        tasks.push(limit(async () => {
          try {
            const fileUrl = `${url.replace(/\/$/, '')}/${file}`;
            const response = await axios.head(fileUrl, { timeout: 3000 });
            if (response.status === 200) {
              foundFiles.push(`${fileUrl} (${response.status})`);
              if (this.verbose && !this.silent) {
                console.log(chalk.cyan(` Found: ${fileUrl}`));
              }
            }
          } catch (err) {}
        }));
      }
    }
    
    await Promise.all(tasks);
    return [...new Set(foundFiles)];
  }

  async discoverFolders(urls) {
    const commonFolders = [
      'admin', 'administrator', 'wp-admin', 'dashboard', 'portal', 'cpanel',
      'api', 'v1', 'v2', 'v3', 'graphql', 'swagger', 'swagger-ui',
      'backup', 'old', 'temp', 'tmp', 'cache', 'logs',
      'uploads', 'images', 'assets', 'static', 'public', 'www',
      'private', 'secret', 'hidden', 'internal', 'dev', 'staging',
      'test', 'testing', 'qa', 'uat', 'sandbox', 'demo'
    ];
    
    const foundFolders = [];
    const limit = pLimit(this.threads);
    
    const tasks = [];
    for (const url of urls.slice(0, 30)) {
      for (const folder of commonFolders) {
        tasks.push(limit(async () => {
          try {
            const folderUrl = `${url.replace(/\/$/, '')}/${folder}/`;
            const response = await axios.get(folderUrl, { 
              timeout: 3000, 
              maxRedirects: 0,
              validateStatus: status => status < 500
            });
            if (response.status === 200 || response.status === 301 || response.status === 302 || response.status === 403) {
              foundFolders.push(`${folderUrl} (${response.status})`);
              if (this.verbose && !this.silent) {
                console.log(chalk.yellow(` Found: ${folderUrl} (${response.status})`));
              }
            }
          } catch (err) {}
        }));
      }
    }
    
    await Promise.all(tasks);
    return [...new Set(foundFolders)];
  }

  async extractEmails(urls) {
    const emails = new Set();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const limit = pLimit(10);
    
    const tasks = [];
    for (const url of urls.slice(0, 50)) {
      tasks.push(limit(async () => {
        try {
          const response = await axios.get(url, { 
            timeout: 5000,
            maxContentLength: 1024 * 1024
          });
          
          const found = response.data.match(emailRegex) || [];
          found.forEach(email => {
            if (!email.includes('example') && !email.includes('test')) {
              emails.add(email);
            }
          });
        } catch (err) {}
      }));
    }
    
    await Promise.all(tasks);
    return Array.from(emails);
  }

  async detectTechnologies(liveResults) {
    const technologies = {};
    
    const techPatterns = {
      'WordPress': [/wp-content/, /wp-includes/, /wp-json/, /wordpress/i],
      'Drupal': [/drupal.js/, /sites\/default\/files/, /Drupal/i, /drupal-/i],
      'Joomla': [/joomla!/i, /\/media\/system\/js\//, /Joomla/i],
      'Laravel': [/laravel/i, /csrf-token/i, /_token/],
      'React': [/react/, /react-dom/, /_reactRoot/, /ReactDOM/],
      'Angular': [/ng-version/, /angular/i, /ng-app/],
      'Vue.js': [/vue\.js/, /vue-router/, /v-data/, /vue-/i],
      'jQuery': [/jquery/i, /\$\(document\)\.ready/],
      'Bootstrap': [/bootstrap/i, /popper/, /data-bs-/],
      'Tailwind': [/tailwind/i, /tw-/, /class=".*?tw-/],
      'Nginx': [/nginx/i],
      'Apache': [/apache/i],
      'Cloudflare': [/cloudflare/i, /__cfduid/, /cf-ray/],
      'AWS': [/aws-amplify/, /amazonaws/, /x-amz-/],
      'Google Analytics': [/google-analytics/, /ga\.js/, /gtag/, /UA-\d+/],
      'Facebook Pixel': [/fbq\(/, /facebook\.com\/tr/],
      'Microsoft IIS': [/iis/i, /Microsoft-IIS/],
      'Express.js': [/express/i, /x-powered-by: express/i],
      'Django': [/django/i, /csrfmiddlewaretoken/],
      'Ruby on Rails': [/rails/i, /csrf-param/, /authenticity_token/],
      'PHP': [/.php$/, /PHPSESSID/]
    };
    
    for (const result of liveResults) {
      try {
        const response = await axios.get(result.url, { 
          timeout: 3000,
          maxContentLength: 512 * 1024
        });
        
        const html = response.data;
        const headers = response.headers;
        
        for (const [tech, patterns] of Object.entries(techPatterns)) {
          for (const pattern of patterns) {
            if (pattern.test(html) || (headers.server && pattern.test(headers.server))) {
              if (!technologies[tech]) {
                technologies[tech] = { count: 0, urls: [] };
              }
              technologies[tech].count++;
              if (!technologies[tech].urls.includes(result.url)) {
                technologies[tech].urls.push(result.url);
              }
            }
          }
        }
      } catch (err) {}
    }
    
    const formattedTech = {};
    for (const [tech, data] of Object.entries(technologies)) {
      formattedTech[tech] = `${data.count} site(s)`;
    }
    
    return formattedTech;
  }

  async extractJSEndpoints(urls) {
    const endpoints = new Set();
    const endpointRegex = /["'](\/(?:api|v\d|rest|graphql|wp-json|auth|user|admin|login|signup|upload|download)[^"'\s?#]*)["']/gi;
    const limit = pLimit(10);
    
    const tasks = [];
    for (const url of urls.slice(0, 30)) {
      tasks.push(limit(async () => {
        try {
          const response = await axios.get(url, { 
            timeout: 5000,
            maxContentLength: 1024 * 1024
          });
          
          const jsRegex = /<script[^>]+src=["']([^"']+\.js)["']/gi;
          let match;
          while ((match = jsRegex.exec(response.data)) !== null) {
            let jsUrl = match[1];
            if (!jsUrl.startsWith('http')) {
              jsUrl = new URL(jsUrl, url).href;
            }
            
            try {
              const jsResponse = await axios.get(jsUrl, { timeout: 3000 });
              const foundEndpoints = jsResponse.data.match(endpointRegex) || [];
              foundEndpoints.forEach(ep => {
                const cleanEp = ep.replace(/["']/g, '');
                if (cleanEp.length > 2 && cleanEp.length < 200) {
                  endpoints.add(cleanEp);
                }
              });
            } catch (err) {}
          }
        } catch (err) {}
      }));
    }
    
    await Promise.all(tasks);
    return Array.from(endpoints).slice(0, 100);
  }

  getStatusColor(statusCode) {
    if (statusCode >= 200 && statusCode < 300) return chalk.green(`[${statusCode}]`);
    if (statusCode >= 300 && statusCode < 400) return chalk.blue(`[${statusCode}]`);
    if (statusCode >= 400 && statusCode < 500) return chalk.yellow(`[${statusCode}]`);
    if (statusCode >= 500) return chalk.red(`[${statusCode}]`);
    return chalk.white(`[${statusCode}]`);
  }

  async saveResults(domain, allResults, liveResults, extraData, outputStream) {
    const timestamp = new Date().toISOString();
    const resultsDir = path.join(process.cwd(), 'results');
    
    const data = {
      domain,
      timestamp,
      scanner: 'SubKamuna v4.0',
      total_subdomains: allResults.length,
      live_services: liveResults.length,
      all_subdomains: allResults,
      live_subdomains: liveResults.map(r => r.displayUrl),
      files_discovered: extraData.files || [],
      folders_discovered: extraData.folders || [],
      emails_extracted: extraData.emails || [],
      technologies_detected: extraData.technologies || {},
      js_endpoints: extraData.jsEndpoints || [],
      platform: os.platform(),
      node_version: process.version
    };
    
    if (outputStream) {
      await outputStream.write(JSON.stringify(data, null, 2) + '\n');
    }
    
    try {
      await fs.mkdir(resultsDir, { recursive: true });
      
      // Save all subdomains
      await fs.writeFile(path.join(resultsDir, `${domain}_all.txt`), allResults.join('\r\n'));
      
      // Save live subdomains
      await fs.writeFile(path.join(resultsDir, `${domain}_live.txt`), liveResults.map(r => r.displayUrl).join('\r\n'));
      
      // Save live URLs only
      await fs.writeFile(path.join(resultsDir, `${domain}_live_urls.txt`), liveResults.map(r => r.url).join('\r\n'));
      
      // Save files
      if (extraData.files?.length) {
        await fs.writeFile(path.join(resultsDir, `${domain}_files.txt`), extraData.files.join('\r\n'));
      }
      
      // Save folders
      if (extraData.folders?.length) {
        await fs.writeFile(path.join(resultsDir, `${domain}_folders.txt`), extraData.folders.join('\r\n'));
      }
      
      // Save emails
      if (extraData.emails?.length) {
        await fs.writeFile(path.join(resultsDir, `${domain}_emails.txt`), extraData.emails.join('\r\n'));
      }
      
      // Save technologies
      if (Object.keys(extraData.technologies || {}).length) {
        const techContent = Object.entries(extraData.technologies)
          .map(([tech, info]) => `${tech}: ${info}`)
          .join('\r\n');
        await fs.writeFile(path.join(resultsDir, `${domain}_technologies.txt`), techContent);
      }
      
      // Save JSON report
      await fs.writeFile(path.join(resultsDir, `${domain}_report.json`), JSON.stringify(data, null, 2));
      
      if (!this.silent && this.verbose) {
        console.log(chalk.gray(`\n[Result] Results saved to: ${resultsDir}/`));
      }
      
    } catch (error) {
      if (this.verbose) {
        console.error(chalk.red(`Error saving results: ${error.message}`));
      }
    }
  }
}

module.exports = Subfinder;