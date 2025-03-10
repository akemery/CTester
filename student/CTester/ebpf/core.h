#ifndef __CORE_H
#define __CORE_H

#define MONITORING(s,y)  skel->bss->ctester_cfg.monitoring_ ## s = y
#define SET_MONITORED_PID(pid)  skel->bss->ctester_cfg.prog_pid = pid
#define ENABLE_MONITORING  skel->bss->ctester_cfg.monitored = true
#define DISABLE_MONITORING  skel->bss->ctester_cfg.monitored = false
#define GET_STATS(s)  skel->bss->ctester_stats.stats_ ## s



#endif /* __CORE_H */
