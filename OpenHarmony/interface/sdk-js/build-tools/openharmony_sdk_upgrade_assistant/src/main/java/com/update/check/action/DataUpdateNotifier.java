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

package com.update.check.action;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * DataUpdateNotifier
 *
 * @since 23-04-07
 */
public class DataUpdateNotifier {
    private static DataUpdateNotifier dataUpdateNotifier = new DataUpdateNotifier();

    private List<UpdateListener> listeners = new ArrayList<>();

    private DataUpdateNotifier() {
    }

    /**
     * DataUpdateNotifier
     *
     * @return return dataUpdateNotifier;
     */
    public static DataUpdateNotifier getInstance() {
        return dataUpdateNotifier;
    }

    /**
     * UpdateListener
     *
     * @since 23-04-07
     */
    public interface UpdateListener {
        /**
         * onUpdate
         *
         * @param chooseType chooseType
         * @param type restart or choose type
         */
        void onUpdate(LinkedHashMap<String, Boolean> chooseType, String type);
    }

    /**
     * notifyDataChange
     *
     * @param chooseType chooseType
     * @param type restart or choose type
     */
    public void notifyDataChange(LinkedHashMap<String, Boolean> chooseType, String type) {
        for (UpdateListener listener : listeners) {
            listener.onUpdate(chooseType, type);
        }
    }

    /**
     * addUpdateListener
     *
     * @param listener listener
     */
    public void addUpdateListener(UpdateListener listener) {
        listeners.add(listener);
    }

}
