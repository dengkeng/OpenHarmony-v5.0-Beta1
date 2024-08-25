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

import fs, { constants } from 'fs';
import path from 'path';
import { LogUtil } from './logUtil';
import type { Stats } from 'fs';

export class FileUtils {
  static readFileContent(file: string): string | undefined {
    return fs.readFileSync(file, 'utf-8');
  }

  static readFilesInDir(dirName: string, filter?: (name: string) => boolean): Array<string> {
    const files: Array<string> = [];
    fs.readdirSync(dirName, { withFileTypes: true }).forEach((dir) => {
      const filePath = path.join(dirName, dir.name);
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
    const parentDir = path.dirname(filePath);
    if (!FileUtils.isExists(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
    fs.writeFileSync(filePath, str);
  }

  static isDirectory(path: string): boolean {
    const stats: Stats = fs.lstatSync(path);
    return stats.isDirectory();
  }

  static isExists(path: string | undefined): boolean {
    if (!path) {
      return false;
    }
    try {
      fs.accessSync(path, constants.R_OK);
      return true;
    } catch (exception) {
      return false;
    }
  }

  static getFileTimeStamp(): string {
    const now = new Date();
    return `${now.getFullYear()}_${now.getMonth() + 1}_${now.getDate()}_${now.getHours()}_${now.getMinutes()}_${now.getSeconds()}`;
  }
}