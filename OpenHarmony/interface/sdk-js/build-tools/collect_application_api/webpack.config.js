/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const path = require('path');
const fs = require('fs');
const webpack = require('webpack');
const archiver = require('archiver');
const packageJson = require('./package.json');
const { copyESLibs } = require('./scripts/copylibs');

class PackPlugin {

  apply(compiler) {
    compiler.hooks.done.tap('PackPlugin', (stats) => {
      const bundleName = 'api-collector.js';
      const bundlejsPath = path.resolve(__dirname, 'dist', 'build', bundleName);
      if (!fs.existsSync(bundlejsPath)) {
        console.error(`${bundleName} not found`);
        return;
      }
      copyESLibs();
      const libsPath = path.resolve(__dirname, 'libs');
      const readme = path.resolve(__dirname, 'reademe.md');
      const outputName = path.resolve(__dirname, 'dist', `apiCollector-${packageJson.version}.zip`);
      const outputZipStream = fs.createWriteStream(outputName);
      const archive = archiver('zip');
      archive.pipe(outputZipStream);
      archive.file(bundlejsPath, { name: bundleName });
      archive.file(readme, { name: 'README.md' });
      archive.directory(libsPath, 'libs');
      archive.finalize();
    });
  }
}

module.exports = {
  entry: './src/entry/main.js',
  mode: 'none',
  target: 'node',
  output: {
    path: path.resolve(__dirname, 'dist', 'build'),
    filename: 'api-collector.js',
  },
  // webpack v4+ 优先使用 package.json 中的 module 字段，json5 配置了 module 字段并且
  // 通过 default 导出，因此在打包之后会出现 JSON5.parse 找不到(实际上为JSON5.default.parse)
  // 优先选择 main 字段
  resolve: {
    mainFields: ['main', 'module', 'browser'],
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.bundleMode': true,
    }),
    new PackPlugin()
  ],
};