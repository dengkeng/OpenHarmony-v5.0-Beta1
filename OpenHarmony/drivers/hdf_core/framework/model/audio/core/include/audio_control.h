/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef AUDIO_CONTROL_H
#define AUDIO_CONTROL_H

#include "hdf_dlist.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define AUDIO_ELEMENT_NAME_LEN 64

struct AudioCtrlElemId {
    const char *cardServiceName;
    int32_t iface;
    const char *itemName; /* ASCII name of item */
};

struct AudioCtlElemListReport {
    char name[AUDIO_ELEMENT_NAME_LEN];
    int32_t iface;
};

struct AudioCtlElemList {
    const char *cardServiceName;
    uint32_t count;     /* R: count of all elements */
    uint32_t space;     /* W: count of element IDs to get */
    struct AudioCtlElemListReport *ctlElemListAddr;    /* R: AudioCtrlElemId list addr */
};

struct AudioCtrlElemInfo {
    struct AudioCtrlElemId id;
    uint32_t count; /* count of values */
    int32_t type; /* R: value type - AUDIODRV_CTL_ELEM_IFACE_MIXER_* */
    int32_t min; /* R: minimum value */
    int32_t max; /* R: maximum value */
};

struct AudioCtrlElemValue {
    struct AudioCtrlElemId id;
    uint32_t value[2];
};

/* enumerated kcontrol */
struct AudioEnumKcontrol {
    uint32_t reg;
    uint32_t reg2;
    uint8_t shiftLeft;
    uint8_t shiftRight;
    uint32_t max;
    uint32_t mask;
    const char * const *texts;
    const uint32_t *values;
    void *sapm;
};

/* mixer control */
struct AudioMixerControl {
    uint32_t min;
    uint32_t max;
    int32_t platformMax;
    uint32_t mask;
    uint32_t reg;
    uint32_t rreg; /* right sound channel reg */
    uint32_t shift;
    uint32_t rshift; /* right sound channel reg shift */
    uint32_t invert;
    uint32_t value;
};

struct AudioKcontrol {
    char *name; /* ASCII name of item */
    int32_t iface;
    int32_t (*Info)(const struct AudioKcontrol *kcontrol, struct AudioCtrlElemInfo *elemInfo);
    int32_t (*Get)(const struct AudioKcontrol *kcontrol, struct AudioCtrlElemValue *elemValue);
    int32_t (*Set)(const struct AudioKcontrol *kcontrol, const struct AudioCtrlElemValue *elemValue);
    void *privateData;
    void *pri;
    unsigned long privateValue;
    struct DListHead list; /* list of controls */
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
