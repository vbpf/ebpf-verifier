#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"

__section("xdp")
static int xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see p4c-xdp project */
    printt("return XDP_PASS\n");
    return XDP_PASS;
}

__section("af_xdp")
static int af_xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see xdpsock_kern.c ans xdpsock_user.c */
    return XDP_PASS;
}
