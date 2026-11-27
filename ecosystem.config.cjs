module.exports = {
  apps: [
    {
      name: 'keysafe',
      cwd: __dirname,
      script: './start-api.sh',
      interpreter: '/bin/bash',
      // Vault sessions and unlock throttles are held in this process.
      exec_mode: 'fork',
      instances: 1,
      watch: false,
      exp_backoff_restart_delay: 1000,
      kill_timeout: 10000,
      time: true,
      env: {
        BIND_HOST: '127.0.0.1',
        WEB_VAULT_WRITES: '0',
        PYTHONUNBUFFERED: '1',
      },
    },
  ],
};
