/*
 * © COPYRIGHT 2022 Corporation CAICT All rights reserved.
 *  http://www.caict.ac.cn
 *  https://bitfactory.cn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @author: zhangzhiliang@caict.ac.cn
 * @date: 2023-03-01 16:16:36
 * @file: fmacros.h
 */
#ifndef __HIREDIS_FMACRO_H
#define __HIREDIS_FMACRO_H

#ifndef _AIX
#define _XOPEN_SOURCE 600
#define _POSIX_C_SOURCE 200112L
#endif

#if defined(__APPLE__) && defined(__MACH__)
/* Enable TCP_KEEPALIVE */
#define _DARWIN_C_SOURCE
#endif

#endif
