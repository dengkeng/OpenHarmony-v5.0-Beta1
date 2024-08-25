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

import fs from 'fs';
import path from 'path';
import envConfig from '../config/env';
import { LogUtil } from './logUtil';
import { StringConstant } from '../utils/Constant';
if (!process.env.DIR_NAME) {
  Object.assign(process.env, envConfig);
}
export class FileUtils {
  /**
   * 通过动态环境变量配置项目根目录的地址
   */
  private static baseDirName: string = String(process.env.DIR_NAME);
  /**
   * 获取项目根目录的地址，相关配置可以查看src\config\env.ts中的DIR_NAME配置
   */
  static getBaseDirName(): string {
    return this.baseDirName;
  }
  /**
   * 读取文件，返回满足要求的所有文件路径
   *
   * @param {string} dirName 文件目录
   * @param {(name: string) => boolean} [filter] 文件路径的过滤条件
   * @return {Array<string>}
   */
  static readFilesInDir(dirName: string, filter?: (name: string) => boolean): Array<string> {
    const files: Array<string> = [];
    fs.readdirSync(dirName, { withFileTypes: true }).forEach((dir) => {
      if (dir.name === StringConstant.NOT_SCAN_DIR) {
        return;
      }
      const filePath: string = path.join(dirName, dir.name);
      if (dir.isFile()) {
        if (!filter) {
          files.push(filePath);
          return;
        }
        if (filter(dir.name)) {
          files.push(filePath);
        }
        return;
      }
      files.push(...FileUtils.readFilesInDir(filePath, filter));
    });
    return files;
  }

  static writeStringToFile(str: string, filePath: string): void {
    const parentDir: string = path.dirname(filePath);
    if (!FileUtils.isExists(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
    fs.writeFileSync(filePath, str);
  }

  static isDirectory(path: string): boolean {
    const stats: fs.Stats = fs.lstatSync(path);
    return stats.isDirectory();
  }

  static isFile(path: string): boolean {
    const stats: fs.Stats = fs.lstatSync(path);
    return stats.isFile();
  }

  static isExists(pathName: string | undefined): boolean {
    if (!pathName) {
      return false;
    }
    try {
      fs.accessSync(path.resolve(this.baseDirName, pathName), fs.constants.R_OK);
      return true;
    } catch (exception) {
      const error = exception as Error;
      LogUtil.e(`error filePath`, error.stack ? error.stack : error.message);
      return false;
    }
  }
}
