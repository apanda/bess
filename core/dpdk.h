#ifndef _DPDK_H_
#define _DPDK_H_

/* rte_version.h depends on these but has no #include :( */
#include <stdio.h>
#include <string.h>

#include <rte_version.h>

#ifndef RTE_VER_MAJOR
  //#error DPDK version is not available
  #define RTE_VER_MAJOR 3
  #define RTE_VER_PATCH_LEVEL 0
  #define RTE_VER_PATCH_RELEASE 0
#endif
  #define DPDK_VER(a,b,c) (((a << 16) | (b << 8) | (c)))
  #define DPDK DPDK_VER(RTE_VER_MAJOR,RTE_VER_MINOR,RTE_VER_PATCH_LEVEL)

void init_dpdk(char *prog_name);

#endif
