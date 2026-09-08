const fs = require('fs');
const path = require('path');
const os = require('os');
const chalk = require('chalk');
const api = require('../utils/api');

module.exports = async function () {
    const configPath = path.join(os.homedir(), '.kv-cli', 'config.json');

    if (!fs.existsSync(configPath)) {
        console.log(chalk.yellow("\n⚠️  No active session found. Please run `kv-cli login`."));
        return;
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

    console.log(chalk.cyan.bold("\n--- KeyVault Session Status ---"));
    console.log(`${chalk.blue("Identity:   ")} ${config.email}`);
    console.log(`${chalk.blue("Registry:   ")} ${os.homedir()}${path.sep}.kv-cli`);

    try {
        const projects = await api.projects.getAll(config.token);
        console.log(`${chalk.blue("Workspaces: ")} ${projects.length} accessible projects`);
        console.log(chalk.green("\n✓ Connection Secure - Ready for injection."));
    } catch (err) {
        console.log(chalk.red("\n❌ Session Expired or Offline - Please re-authenticate."));
    }
    console.log("");
};
