/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import Vector from '@ohos.util.Vector';
import { Log, PrinterCapability } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import type { PrintServiceAdapter } from '../PrintServiceAdapter';
import type DiscoveredPrinter from '../discovery/DiscoveredPrinter';
import type { Backend } from '../ipp/Backend';
import type uri from '@ohos.uri';

const TAG = 'CapabilitiesCache';

export class CapabilitiesCache {
  private readonly mPrintServiceAdapter: PrintServiceAdapter;
  private readonly mBackend: Backend;
  private readonly requestVector: Vector<Request> = new Vector<Request>();
  private currentRequest: Request;

  constructor(printServiceAdapter: PrintServiceAdapter) {
    this.mPrintServiceAdapter = printServiceAdapter;
    this.mBackend = this.mPrintServiceAdapter.backend;
  }

  /**
   * request printer caps
   *
   * @param printer
   * @param onLocalPrinterCapabilities
   */
  public async requestCapabilities(printer: DiscoveredPrinter, onLocalPrinterCapabilities: OnLocalPrinterCapabilities): Promise<void> {
    if (CheckEmptyUtils.isEmpty<DiscoveredPrinter>(printer)) {
      Log.error(TAG, 'printer is empty');
      return;
    }
    if (CheckEmptyUtils.isEmpty<uri.URI>(printer.getUri())) {
      Log.error(TAG, 'uri is empty');
      return;
    }
    let uri = printer.getUri();
    Log.debug(TAG, 'caps not in cache, request from printer');
    let request = new Request(this.mBackend, uri, printer.getDeviceName(), onLocalPrinterCapabilities);
    this.requestVector.add(request);
    this.startNextRequest();
  }

  private startNextRequest(): void {
    Log.debug(TAG, 'startNextRequest enter');
    if (this.requestVector.length === 0) {
      Log.error(TAG, 'no active request in requestVector');
      return;
    }
    if (this.currentRequest !== undefined) {
      Log.error(TAG, 'a active request is running, requestVector len: ' + this.requestVector.length);
      return;
    }
    this.currentRequest = this.requestVector.removeByIndex(0);
    if (CheckEmptyUtils.isEmpty<Request>(this.currentRequest)) {
      Log.error(TAG, 'currentRequest is empty');
      return;
    }
    this.currentRequest.start(() => {
      Log.info(TAG, 'Previous request complete, start next request');
      this.currentRequest = undefined;
      this.startNextRequest();
    });
  }

  public close(): void {
    Log.info(TAG, 'close');
  }
}

class Request {
  constructor(private backend: Backend, private uri: uri.URI, private printerName: string, private capsCallback: OnLocalPrinterCapabilities) {
    this.backend = backend;
    this.uri = uri;
    this.printerName = printerName;
    this.capsCallback = capsCallback;
  }

  public start(requestCallback: () => void): void {
    this.backend.getCapabilities(this.uri, this.printerName, this.capsCallback, requestCallback);
  }
}


/**
 * Callback for receiving capabilities
 */
export interface OnLocalPrinterCapabilities {

  /**
  * Called when capabilities are retrieved
  *
  * @param capabilities PrinterCapability
  */
  onCapabilities(capabilities: PrinterCapability): void;

}