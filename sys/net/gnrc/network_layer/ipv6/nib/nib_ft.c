/*
 * SPDX-FileCopyrightText: 2017 Freie Universität Berlin
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "_nib-internal.h"

#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/ipv6/nib/ft.h"

#define ENABLE_DEBUG 1
#include "debug.h"

int gnrc_ipv6_nib_ft_get(const ipv6_addr_t *dst, gnrc_pktsnip_t *pkt,
                         gnrc_ipv6_nib_ft_t *fte)
{
    int res;

    assert((dst != NULL) && (fte != NULL));
    _nib_acquire();
    res = _nib_get_route(dst, pkt, fte);
    _nib_release();
    return res;
}

int gnrc_ipv6_nib_ft_add(const ipv6_addr_t *dst, unsigned dst_len,
                         const ipv6_addr_t *next_hop, unsigned iface,
                         uint32_t ltime)
{
    int res = 0;
    bool is_default_route = ((dst == NULL) || (dst_len == 0) ||
                             ipv6_addr_is_unspecified(dst));

    uint32_t ltime_ms;
    /* The valid lifetime is given in seconds, but our timers work in
     * milliseconds, so we have to scale down to the smallest possible
     * value (UINT32_MAX ms). This is however alright since we ask for
     * a new router advertisement before this timeout expires */
    if (ltime > UINT32_MAX / MS_PER_SEC) {
        ltime_ms = UINT32_MAX;
    }
    else {
        ltime_ms = ltime * MS_PER_SEC;
    }
    if ((iface == 0) || ((is_default_route) && (next_hop == NULL))) {
        return -EINVAL;
    }
    _nib_acquire();
    if (is_default_route) {
        _nib_dr_entry_t *ptr;

        ptr = _nib_drl_add(next_hop, iface);
        if (ptr == NULL) {
            res = -ENOMEM;
        }
        else {
            _prime_def_router = ptr;
            if (ltime_ms > 0) {
                _evtimer_add(ptr, GNRC_IPV6_NIB_RTR_TIMEOUT,
                             &ptr->rtr_timeout, ltime_ms);
            }
        }
    }
#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_ROUTER)

    else if (ipv6_addr_is_multicast(dst)) {
        _nib_offl_mc_entry_t *ptr;

        dst_len = (dst_len > 128) ? 128 : dst_len;

        ptr = _nib_ft_mc_add(next_hop, iface, dst, dst_len, ltime_ms);
        if (ptr == NULL) {
            res = -ENOMEM;
        }

    }
    else {
        _nib_offl_entry_t *ptr;

        dst_len = (dst_len > 128) ? 128 : dst_len;
        ptr = _nib_ft_add(next_hop, iface, dst, dst_len);
        if (ptr == NULL) {
            res = -ENOMEM;
        }
        else if (ltime_ms > 0) {
            _evtimer_add(ptr, GNRC_IPV6_NIB_ROUTE_TIMEOUT,
                         &ptr->route_timeout, ltime_ms);
        }
    }
#else /* CONFIG_GNRC_IPV6_NIB_ROUTER */
    else {
        res = -ENOTSUP;
    }
#endif
    _nib_release();
    return res;
}

void gnrc_ipv6_nib_ft_del(const ipv6_addr_t *dst, unsigned dst_len)
{
    _nib_acquire();
    if ((dst == NULL) || (dst_len == 0) || ipv6_addr_is_unspecified(dst)) {
        _nib_dr_entry_t *entry = _nib_drl_get_dr();

        if (entry != NULL) {
            _nib_drl_remove(entry);
        }
    }
#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_ROUTER)
    else {

        if (ipv6_addr_is_multicast(dst)) 
        {
            _nib_offl_mc_entry_t *entry = NULL;
            while ((entry = _nib_offl_mc_iter(entry))) 
            {
                if ((entry->pfx_len == dst_len) &&
                    (ipv6_addr_match_prefix(&entry->pfx, dst) >= dst_len)) {
                    _nib_ft_mc_remove(entry);
                    break;
                } 
            }
        } else {
            _nib_offl_entry_t *entry = NULL;

            while ((entry = _nib_offl_iter(entry))) {
                if ((entry->pfx_len == dst_len) &&
                    (ipv6_addr_match_prefix(&entry->pfx, dst) >= dst_len)) {
                    _nib_ft_remove(entry);
                    break;
                }
            }
        }        
    }
#endif
    _nib_release();
}

bool gnrc_ipv6_nib_ft_iter(const ipv6_addr_t *next_hop, unsigned iface,
                          void **state, gnrc_ipv6_nib_ft_t *fte)
{
    _nib_dr_entry_t *entry;
    assert((state != NULL) && (fte != NULL));

    if ((*state == NULL) || _nib_offl_is_entry(*state)) {
        _nib_offl_entry_t *offl = *state;

        while ((offl = _nib_offl_iter(offl))) {
            assert(offl->mode != 0);
            if (offl->next_hop == NULL) {
                /* 'holey' NIB / dangling reference.
                 * there is no next hop (not even an interface) */
                continue;
            }
            if (offl->mode == _PL && !(offl->flags & _PFX_ON_LINK)) {
                /* prefix list entry is off-link */
                continue;
            }
            if (iface && iface != _nib_onl_get_if(offl->next_hop)) {
                /* interface does not match */
                continue;
            }
            if (next_hop && !ipv6_addr_equal(&offl->next_hop->ipv6, next_hop)) {
                /* next hop does not match */
                continue;
            }
            _nib_ft_get(offl, fte);
            *state = offl;
            return true;
        }
        *state = NULL;
    }

    if ((*state == NULL) || _nib_offl_mc_is_entry(*state)){
         _nib_offl_mc_entry_t *offl_mc = *state;

        while ((offl_mc = _nib_offl_mc_iter(offl_mc))) {
            assert(offl_mc->mode != 0);
            if (offl_mc->num_next_hops == 0) {
                /* 'holey' NIB / dangling reference.
                 * there is no next hop */
                continue;
            }
            if (iface && iface != _nib_onl_get_if(offl_mc->next_hop_list[0].next_hop)) {
                /* interface does not match */
                DEBUG("NIB: FT ITER: Interface does not match.\n");
                continue;
            }
            bool hop_matches = false;
            for (u_int8_t i = 0; i < offl_mc->num_next_hops; i++)
            {
                _nib_onl_entry_t *nh = offl_mc->next_hop_list[i].next_hop;
                if (next_hop && ipv6_addr_equal(&nh->ipv6, next_hop)) {
                    hop_matches = true;
                    break;
                }
            }
            if (next_hop && !hop_matches)
            {   
                DEBUG("NIB: FT ITER: no entry matches.\n");
                continue;
            }
            _nib_ft_mc_get(offl_mc, fte);
            *state = offl_mc;
            return true;
        }
        *state = NULL;
    }
       
    entry = *state;
    
    /*TODO: guard entry against being something else then _nib_dr_entry_t ??*/
    while ((entry = _nib_drl_iter(entry))) {
        if ((entry->next_hop != NULL) &&
            ((iface == 0) || (iface == _nib_onl_get_if(entry->next_hop))) &&
            ((next_hop == NULL) || ipv6_addr_equal(&entry->next_hop->ipv6,
                                                   next_hop))) {
            _nib_drl_ft_get(entry, fte);
            break;
        }
    }
    *state = entry;
    return (*state != NULL);
}

void gnrc_ipv6_nib_ft_print(const gnrc_ipv6_nib_ft_t *fte)
{
    char addr_str[IPV6_ADDR_MAX_STR_LEN];

    if ((fte->dst_len == 0) || ipv6_addr_is_unspecified(&fte->dst)) {
        printf("default%s ", (fte->primary ? "*" : ""));
    }
    else {
        printf("%s/%u ", ipv6_addr_to_str(addr_str, &fte->dst, sizeof(addr_str)),
        fte->dst_len);
    }

    if (ipv6_addr_is_multicast(&fte->dst)) {
        /* MCAST: iterate over fte child list*/
        printf("MC via: ");
        for (u_int8_t i = 0; i < (fte->num_next_hops); i++)
        {
            printf(" %s ", ipv6_addr_to_str(addr_str, &fte->next_hop_list[i], sizeof(addr_str)));
        }
    }
    
    if (!ipv6_addr_is_unspecified(&fte->next_hop)) {
    printf("via %s ", ipv6_addr_to_str(addr_str, &fte->next_hop,
                                    sizeof(addr_str)));
    }
    printf("dev #%u\n", fte->iface);
}

/** @} */
