/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef SATELLITE_RADIO_EVENT_H
#define SATELLITE_RADIO_EVENT_H
enum SatelliteRadioEvent {
    SATELLITE_RADIO_DIAL = 2001,
    SATELLITE_RADIO_HANGUP,
    SATELLITE_RADIO_ANSWER,
    SATELLITE_RADIO_REJECT,
    SATELLITE_RADIO_GET_CALL_DATA,
    SATELLITE_RADIO_CALL_STATE_CHANGED,
};
#endif // SATELLITE_RADIO_EVENT_H
