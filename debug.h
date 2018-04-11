/******************************************************************************
*
* INTEL CONFIDENTIAL
*
* Copyright 2015 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related
* to the source code (Material) are owned by Intel Corporation or its
* suppliers or licensors. Title to the Material remains with
* Intel Corporation or its suppliers and licensors. The Material contains
* trade secrets and proprietary and confidential information of Intel or
* its suppliers and licensors. The Material is protected by worldwide
* copyright and trade secret laws and treaty provisions. No part of the
* Material may be used, copied, reproduced, modified, published, uploaded,
* posted, transmitted, distributed, or disclosed in any way without Intel's
* prior express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise. Any license under such intellectual property rights
* must be express and approved by Intel in writing.
*
*
*   Workfile:   FwUpdateDebug.c
*
*   Abstract:   macros to wrap dbglog for simple FwUpdate debugging
*
******************************************************************************/

#ifndef __FW_UPDATE_DEBUG_H__
#define __FW_UPDATE_DEBUG_H__

#include <gsl/span>
#include <iostream>

typedef enum {
  PRINT_NONE = 0,
  PRINT_CRITICAL = 1,
  PRINT_ERROR,
  PRINT_WARNING,
  PRINT_INFO,
  PRINT_DEBUG,
  PRINT_DEBUG2,
  PRINT_ALL,
} dbg_level;

#define FWCRITICAL(MSG) PRINT(PRINT_CRITICAL, MSG)
#define FWERROR(MSG) PRINT(PRINT_ERROR, MSG)
#define FWWARN(MSG) PRINT(PRINT_WARNING, MSG)
#define FWINFO(MSG) PRINT(PRINT_INFO, MSG)
#define FWDEBUG(MSG) PRINT(PRINT_DEBUG, MSG)
#define FWDEBUG2(MSG) PRINT(PRINT_DEBUG2, MSG)

#define FWDUMP(D, L) DUMP(PRINT_DEBUG, D, L)

#define FW_UPDATE_DEBUG 1

#ifdef FW_UPDATE_DEBUG

extern dbg_level fw_update_get_dbg_level(void);
extern void fw_update_set_dbg_level(dbg_level l);

#define PRINT(LEVEL, MSG)                                                  \
  do {                                                                     \
    if ((LEVEL) <= fw_update_get_dbg_level()) {                            \
      std::stringstream ss;                                                \
      ss << '<' << LEVEL << '>' << __FUNCTION__ << ":" << __LINE__ << ": " \
         << MSG;                                                           \
      std::cerr << ss.str() << std::endl;                                  \
    }                                                                      \
  } while (0)

void _dump(dbg_level lvl, const char *fn, int lineno, const char *bname,
           const gsl::span<const uint8_t> &buf);

void _dump(dbg_level lvl, const char *fn, int lineno, const char *bname,
           const void *buf, size_t len);

#define DUMP(LEVEL, BUF, ...)                                         \
  do {                                                                \
    if ((LEVEL) <= fw_update_get_dbg_level()) {                       \
      _dump(LEVEL, __FUNCTION__, __LINE__, #BUF, BUF, ##__VA_ARGS__); \
    }                                                                 \
  } while (0)

#else /* !FW_UPDATE_DEBUG */

#define PRINT(...)
#define DUMP(...)

#endif /* FW_UPDATE_DEBUG */

#endif /* __FW_UPDATE_DEBUG_H__ */
