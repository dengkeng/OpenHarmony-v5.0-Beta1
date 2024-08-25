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

const commander = require('commander');
const toolboxConfig = require('./toolbox.config');
class ToolBoxCommander {
  program = new commander.Command();
  constructor() {}

  addPluginCommand(plugin) {
    const pluginOption = plugin.getPluginOptions();
    if (!pluginOption) {
      return;
    }
    const pluginCommand = this.program.name(pluginOption.name)
      .description(pluginOption.description)
      .version(pluginOption.version)
      .action((opts) => {
        plugin.start(opts);
        plugin.stop();
      });
    pluginOption.commands.forEach((command) => {
      if (command.isRequiredOption) {
        pluginCommand.requiredOption(...command.options);
      } else {
        pluginCommand.option(...command.options);
      }
    });
  }

  buildCommands() {
    this.program.parse();
  }
}
class ToolboxEntry {
  commandBuilder;
  constructor() {
    this.commandBuilder = new ToolBoxCommander();
  }

  runPlugins() {
    const configuration = toolboxConfig.getToolConfiguration();
    configuration.plugins.forEach((plugin) => {
      this.commandBuilder.addPluginCommand(plugin);
    });
    this.commandBuilder.buildCommands();
  }
}
function main() {
  const entry = new ToolboxEntry();
  entry.runPlugins();
}
main();