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

const { ApiCollector, MultiProjectApiCollector } = require('./api_collector');
const { Logger } = require('./utils');
const path = require('path');
const fs = require('fs');

class AppApiCollectorPlugin {
  constructor() {
    this.logTag = 'AppApiCollectorPlugin';
  }
  getPluginOptions() {
    return {
      name: 'api-collector',
      version: '0.1.0',
      description: 'collect api from app\'s source code.',
      commands: [
        {
          isRequiredOption: false,
          options: ['--app <string>', 'app root directory'],
        },
        {
          isRequiredOption: false,
          options: ['--appDir <string>', 'a path that contains multiple applications'],
        },
        {
          isRequiredOption: false,
          options: ['--sdk <string>', 'sdk path, need to specify the ets directory, e.g sdk-root/version/ets'],
        },
        {
          isRequiredOption: false,
          options: ['--sdkRoot <string>', 'sdk root path'],
        },
        {
          isRequiredOption: false,
          options: ['--output <string>', 'the path to output the report'],
        },
        {
          isRequiredOption: false,
          options: ['--format <json,excel>', 'format of the output report'],
        },
        {
          isRequiredOption: false,
          options: ['--scanTest', 'scan ohosTest'],
        },
        {
          isRequiredOption: false,
          options: ['--debug', 'output debug logs'],
        },
        {
          isRequiredOption: false,
          options: ['--noRepeat', 'apiInfos is not repeat']
        }
      ],
    };
  }

  async start(argv) {
    if (!this.checkArguments(argv)) {
      return;
    }
    const startTime = Date.now();
    if (argv.app) {
      await this.scanSingleProject(argv);
    } else if (argv.appDir) {
      await this.scanMultiProject(argv);
    } else if (argv.dir) {
      await this.scanNonProject(argv);
    } else {
      Logger.info(this.logTag, 'see --help');
    }
    Logger.info(this.logTag, `elapsed time ${Date.now() - startTime}`);
    if (argv.debug) {
      Logger.flush(this.getLogPath(argv));
    }
  }

  async scanSingleProject(argv) {
    const collector = new ApiCollector(argv);
    await collector.setLibPath(this.findLibPath()).setIncludeTest(argv.scanTest).start();
  }

  async scanMultiProject(argv) {
    if (!argv.sdk) {
      const collector = new MultiProjectApiCollector(argv);
      await collector.setLibPath(this.findLibPath()).setIncludeTest(argv.scanTest).start();
    } else {
      Logger.error(this.logTag, '--appDir and --sdkRoot are used together, replace --sdk with --sdkRoot');
    }
  }

  async scanNonProject(argv) {
    if (!argv.sdk) {
      Logger.error(this.logTag, 'the --sdk is required when scanning non-project');
      return;
    }
    const apiCollector = new ApiCollector(argv);
    await apiCollector.setLibPath(this.findLibPath()).start();
  }

  getLogPath(argv) {
    if (argv.output) {
      return argv.output;
    }
    if (argv.appDir) {
      return argv.appDir;
    }
    if (argv.app) {
      return argv.app;
    }
    return __dirname;
  }

  findLibPath() {
    if (process.env.bundleMode) {
      return path.resolve(__dirname, 'libs');
    }
    return path.resolve(__dirname, '..', 'libs');
  }

  stop() {

  }

  checkArguments(argv) {
    if (argv.sdk) {
      const apiPath = path.resolve(argv.sdk, 'api');
      const componentPath = path.resolve(argv.sdk, 'component');
      if (!fs.existsSync(apiPath) || !fs.existsSync(componentPath)) {
        Logger.error(this.logTag, '--sdk option need to specify the ets directory');
        return false;
      }
    }
    return this.checkPathIsValid(argv.app) &&
      this.checkPathIsValid(argv.output) &&
      this.checkPathIsValid(argv.sdkRoot) &&
      this.checkPathIsValid(argv.appDir);
  }

  checkPathIsValid(path) {
    if (path && !fs.existsSync(path)) {
      Logger.error(this.logTag, `${path} not exists`);
      return false;
    }
    return true;
  }
}

module.exports = AppApiCollectorPlugin;