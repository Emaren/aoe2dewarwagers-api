module.exports = {
  apps: [
    {
      name: 'aoe2dewarwagers-api',
      cwd: '/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn',
      script: '/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn/venv/bin/python',
      args: '-m uvicorn app:app --host 127.0.0.1 --port 4400',
      interpreter: 'none',
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        ENV: 'production',
        PYTHONPATH: '/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn',
        DOTENV_CONFIG_PATH: '/mnt/HC_Volume_105319120/www-moved/AoE2DEWarWagers/api-prodn/.env.production',
      },
      error_file: '/root/.pm2/logs/aoe2dewarwagers-api-error.log',
      out_file:   '/root/.pm2/logs/aoe2dewarwagers-api-out.log',
    },
  ],
};
