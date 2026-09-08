const fs = require('fs');
const path = require('path');
const os = require('os');
const chalk = require('chalk');

module.exports = async function () {
    const configDir = path.join(os.homedir(), '.kv-cli');
    const configPath = path.join(configDir, 'config.json');

    if (fs.existsSync(configPath)) {
        fs.unlinkSync(configPath);
        console.log(chalk.green("\n👋 Session terminated. Local registry wiped."));
    } else {
        console.log(chalk.yellow("\nNo active session found. You are already logged out."));
    }
};
