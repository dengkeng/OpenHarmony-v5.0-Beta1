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

import commander from 'commander';
import envConfig from './config/env';
import { getToolConfiguration, ToolConfigType } from './bin/index';
import { CommandType, OptionObjType, PluginType, PluginOptionsType, toolNameType, toolNameSet } from './bin/config';
import { LogUtil } from './utils/logUtil';
import { FileUtils } from './utils/FileUtils';

class ToolBoxCommander {
  program: commander.Command = new commander.Command();
  constructor() { }
  addPluginCommand(plugin: PluginType): void {
    const pluginOption: PluginOptionsType = plugin.pluginOptions;
    if (!pluginOption) {
      return;
    }
    const pluginCommand: commander.Command = this.program
      .name(pluginOption.name)
      .description(pluginOption.description)
      .version(pluginOption.version)
      .action((opts: OptionObjType) => {
        this.judgeOpts(opts);
        plugin.start(opts);
        plugin.stop();
      });
    pluginOption.commands.forEach((command: CommandType) => {
      if (command.isRequiredOption) {
        pluginCommand.requiredOption(...command.options);
      } else {
        pluginCommand.option(...command.options);
      }
    });
  }
  buildCommands(): void {
    this.program.parse();
  }
  /**
   * 判断传入命令是否满足工具允许条件，满足正常允许，不满足的时候通过stopRun停止命令行执行
   *
   * @param {OptionObjType} opts
   */
  judgeOpts(opts: OptionObjType): void {
    const toolName: string = opts.toolName;
    if (!toolNameSet.has(toolName)) {
      this.stopRun(`error toolName "${toolName}",toolName not in \[${[...toolNameSet]}\] `);
    }
    switch (toolName) {
      case toolNameType.COLLECT:
        const collectPath: string = opts.collectPath;
        if (collectPath === '' || !FileUtils.isExists(collectPath)) {
          this.stopRun(`error collectPath "${collectPath}",collectPath need a exist file path`);
        }
        break;
      case toolNameType.LABELDETECTION:
        const checkLabels: string = opts.checkLabels;
        if (checkLabels === '') {
          this.stopRun(`error checkLabels "${checkLabels}",detection tools need checkLabels`);
        }
    }
  }
  /**
   * 停止命令行执行，输出错误信息
   *
   * @param {string} text
   */
  stopRun(text: string): void {
    LogUtil.e('commander', text);
    this.program.help({ error: true });
  }
}
class ToolboxEntry {
  commandBuilder: ToolBoxCommander;
  constructor() {
    this.commandBuilder = new ToolBoxCommander();
  }
  runPlugins(): void {
    const configuration: ToolConfigType = getToolConfiguration();
    configuration.plugins.forEach((plugin: PluginType) => {
      this.commandBuilder.addPluginCommand(plugin);
    });
    this.commandBuilder.buildCommands();
  }
}

function main(): void {
  Object.assign(process.env, envConfig);
  const entry = new ToolboxEntry();
  entry.runPlugins();
}

main();
