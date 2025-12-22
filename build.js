const esbuild = require('esbuild');

esbuild
  .build({
    entryPoints: ['app.js'],
    bundle: true,
    platform: 'browser',
    outfile: 'bundle.js',
  })
  .catch(() => process.exit(1));
