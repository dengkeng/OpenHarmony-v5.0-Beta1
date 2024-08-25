/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

let eventMap = {}

export const emit = (event, ...argument) => {
  if (Array.isArray(eventMap[event])) {
    eventMap[event].forEach((fn: Function) => {
      fn.apply(this, argument)
    })
  }
}

export const on = (event, callback) => {
  if (!eventMap[event]) {
    eventMap[event] = []
  }
  eventMap[event].push(callback)
}

export const off = (event, callback, flag = true) => {
  if (flag) {
    const index = eventMap[event].indexOf(item => item === callback)
    if (index !== -1) {
      eventMap[event].splice(index, 1)
    }
  } else {
    eventMap[event] = []
  }
}