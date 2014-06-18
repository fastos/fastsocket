/*
 * fcoe compat definitions
 */
#ifndef _FCOE_COMPAT_
#define _FCOE_COMPAT_

int fcoe_transport_create(const char *, struct kernel_param *);
int fcoe_transport_destroy(const char *, struct kernel_param *);
int fcoe_transport_enable(const char *, struct kernel_param *);
int fcoe_transport_disable(const char *, struct kernel_param *);

#endif
