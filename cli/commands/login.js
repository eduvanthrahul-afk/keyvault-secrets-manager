const readline = require('readline');
const fs = require('fs');
const path = require('path');
const os = require('os');
const api = require('../utils/api');
const cryptoUtils = require('../utils/crypto');
const chalk = require('chalk');
const figlet = require('figlet');
const { writeEncrypted } = require('../utils/cryptoConfig');

function prompt(query) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

module.exports = async function () {
    console.log(
        chalk.cyan(
            figlet.textSync('KeyVault', { horizontalLayout: 'full' })
        )
    );
    console.log(chalk.bold.magenta("🚀 True Zero-Knowledge Dev Platform CLI\n"));

    const email = await prompt(chalk.blue("✉️   Email: "));
    const password = await prompt(chalk.blue("🔑  Password: "));

    try {
        console.log("Fetching secure salt...");
        const saltRes = await api.auth.getSalt(email);
        const salt = saltRes.salt;

        console.log("Generating Zero-Knowledge Auth Hash...");
        const authHash = await cryptoUtils.generateAuthHash(password, salt);

        console.log("Authenticating with KeyVault...");
        const response = await api.auth.login(email, authHash);

        const configDir = path.join(os.homedir(), '.kv-cli');
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir);
        }

        const configPath = path.join(configDir, 'config.json');
        fs.writeFileSync(configPath, JSON.stringify({
            token: response.token,
            email: response.email,
            salt: response.salt,
            encryptedPrivateKey: response.encryptedPrivateKey
        }, null, 2));

        console.log(chalk.green("\n✅ Successfully authenticated and bootstrapped Zero-Knowledge environment."));
        console.log(chalk.gray(`Config saved to ${configPath}\n`));
    } catch (err) {
        console.error(chalk.red("\n❌ Login failed:"));
        console.error(chalk.red(err.response ? err.response.data : err.message));
        process.exit(1);
    }
};
