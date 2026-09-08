const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const readline = require('readline');
const inquirer = require('inquirer');
const api = require('../utils/api');
const cryptoUtils = require('../utils/crypto');
const chalk = require('chalk');
const crypto = require('crypto');

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

module.exports = async function (cmdArray, options) {
    let projectId = options.project;
    let token = options.token || process.env.KV_TOKEN;

    try {
        let projectKeyObj;
        let authToken = null;

        if (token) {
            // CI/CD / Machine Token Flow
            console.log(chalk.cyan("🤖 Machine Identity detected. Authenticating via token..."));
            const parts = token.split('.');
            if (parts.length !== 2) throw new Error("Invalid token format. Expected kv_id.secret");

            const tokenId = parts[0];
            const tokenSecret = parts[1];

            const tokenHash = crypto.createHash('sha256').update(tokenSecret).digest('hex');

            const verifyRes = await api.tokens.verify(tokenId, tokenHash);
            projectId = verifyRes.projectId;

            projectKeyObj = await cryptoUtils.unwrapProjectKeyWithToken(verifyRes.encryptedProjectKey, tokenSecret);

            // We still need a temporary token to fetch the keys. 
            // In a real system, the Machine Token would grant a session.
            // For this MVP, we'll assume the CLI user is logged in, OR we'd need to add machine-auth to the backend.
            // Let's check if we have a local config.
            const configPath = path.join(os.homedir(), '.kv-cli', 'config.json');
            if (fs.existsSync(configPath)) {
                authToken = JSON.parse(fs.readFileSync(configPath, 'utf-8')).token;
            } else {
                // If no local config, we need to allow the backend to fetch keys with a Machine Token.
                // For now, let's assume the user has logged in once.
                throw new Error("Machine token requires a local session for key retrieval in this version.");
            }

        } else {
            // Interactive User Flow
            const configPath = path.join(os.homedir(), '.kv-cli', 'config.json');
            if (!fs.existsSync(configPath)) {
                console.error(chalk.red("❌ No config found. Please run `kv-cli login` first or provide --token."));
                process.exit(1);
            }
            const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
            authToken = config.token;

            // Interactive Selection if project ID is missing
            if (!projectId) {
                console.log(chalk.cyan("Fetching project blueprints..."));
                let projects = await api.projects.getAll(authToken);
                if (projects.length === 0) {
                    console.log(chalk.yellow("No projects found in your registry."));
                    process.exit(0);
                }
                const answer = await inquirer.prompt([{
                    type: 'list',
                    name: 'projectId',
                    message: 'Select a project architecture to unlock:',
                    choices: projects.map(p => ({ name: `${p.name} ${chalk.gray(`(${p.tag || 'no-tag'})`)}`, value: p.id }))
                }]);
                projectId = answer.projectId;
            }

            // 1. Ask for Master Password
            console.log(chalk.cyan(`\n🔒 Unlocking vault for project ${projectId}...`));
            const masterPassword = await prompt(chalk.blue("🔑 Enter Master Password (RAM-only decryption): "));

            // 2. Derive Session Key and Unlock RSA Private Key
            const sessionKey = await cryptoUtils.deriveKey(masterPassword, config.salt);
            let rsaPrivateKey = null;
            if (config.encryptedPrivateKey) {
                rsaPrivateKey = await cryptoUtils.decryptAndImportPrivateKey(config.encryptedPrivateKey, sessionKey);
            }

            // 3. Fetch Project Context
            const members = await api.projects.getMembers(authToken, projectId);
            const me = members.find(m => m.email.toLowerCase() === config.email.toLowerCase());

            if (me && me.encryptedProjectKey && rsaPrivateKey) {
                projectKeyObj = await cryptoUtils.unwrapProjectKey(me.encryptedProjectKey, rsaPrivateKey);
            } else {
                console.log(chalk.yellow("ℹ️  Missing specific RSA encrypted key, falling back to legacy algorithm..."));
                projectKeyObj = await cryptoUtils.getLegacyProjectKey(projectId);
            }
        }

        // 4. Fetch the secrets from the vault
        const keysResponse = await api.keys.getByProject(authToken, projectId);
        const envKeys = keysResponse.filter(k => k.environment.toUpperCase() === options.env.toUpperCase());

        // 5. Decrypt!
        console.log(chalk.green(`\n✅ Decrypted ${envKeys.length} keys for environment: ${options.env}`));
        const secretsEnv = {};
        for (const k of envKeys) {
            const plaintext = await cryptoUtils.decrypt(k.encryptedValue, k.iv, projectKeyObj);
            secretsEnv[k.name] = plaintext;
        }

        // 6. Spawn the command
        if (cmdArray && cmdArray.length > 0) {
            console.log(chalk.magenta.bold(`🚀 Injecting secrets into '${cmdArray.join(' ')}'...\n`));
            const envForChild = { ...process.env, ...secretsEnv };
            const child = spawn(cmdArray[0], cmdArray.slice(1), { env: envForChild, stdio: 'inherit', shell: true });
            child.on('close', (code) => process.exit(code));
        } else {
            console.log(chalk.gray("No command specified. Exiting safely."));
            process.exit(0);
        }

    } catch (err) {
        console.error(chalk.red("\n❌ Execution Failed:"));
        console.error(chalk.red(err.message || err));
        process.exit(1);
    }
};
