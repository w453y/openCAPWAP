#ifndef __KMOD_CONFIG_HEADER__
#define __KMOD_CONFIG_HEADER__

/* Uncomment to enable verbose kernel log tracing */
/* #define DEBUGKMOD 1 */

#ifdef DEBUGKMOD
#define TRACEKMOD(s, args...)   printk(KERN_DEBUG "wtp-kmod: " s, ##args)
#else
#define TRACEKMOD(s, args...)
#endif

#endif /* __KMOD_CONFIG_HEADER__ */
