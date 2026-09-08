#!/usr/bin/env node
const { Command } = require('commander');
const loginCmd = require('../commands/login');
const runCmd = require('../commands/run');
const statusCmd = require('../commands/status');
const logoutCmd = require('../commands/logout');

const program = new Command();

program
    .name('kv-cli')
    .description('Zero-Knowledge Secrets Manager CLI')
    .version('1.0.0')
    .enablePositionalOptions();

program
    .command('login')
    .description('Authenticate with the vault and bootstrap local encryption context')
    .action(loginCmd);

program
    .command('status')
    .description('Check active session status and identity')
    .action(statusCmd);

program
    .command('logout')
    .description('Terminates the local session and wipes sensitive registry files')
    .action(logoutCmd);

program
    .command('run')
    .description('Decrypt vault secrets and optionally inject them into a process')
    .option('-p, --project <id>', 'Project ID to load secrets from')
    .option('--env <env>', 'Environment filter (e.g. dev, prod)', 'dev')
    .option('-t, --token <token>', 'Machine token for CI/CD authentication')
    .allowUnknownOption()
    .passThroughOptions()
    .argument('[cmd...]', 'Command to run (e.g. npm start)')
    .action(runCmd);

program.parse(process.argv);
