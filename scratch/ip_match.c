/*
 * Author: Ugo Varetto - ugo.varetto@csiro.au
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include <stddef.h>   // for size_t
#include <stdint.h>
/*
 * Returns true if the supplied IP address (as a 32‑bit unsigned integer)
 * matches **any** mask in the array according to the rule:
 *
 *        (ip & mask) == ip
 *
 * Parameters
 * ----------
 * ip      : the IP address to test
 * masks   : pointer to an array of masks
 * n_masks : number of elements in the masks array
 *
 * The function does **not** assume any particular ordering or uniqueness of
 * the masks – it simply scans the array until a match is found.
 */
bool ip_matches_any_mask(uint32_t ip, const uint32_t *masks, size_t n_masks)
{
    for (size_t i = 0; i < n_masks; ++i) {
        if ( (ip & masks[i]) == ip )
            return true;            // match found
    }
    return false;                   // no mask satisfied the condition
}

/* -------------------------------------------------------------
   Example usage
   ------------------------------------------------------------- */
#ifdef TEST_IP_MATCH

#include <stdio.h>

int main(void)
{
    uint32_t ip = 0xC0A80105;               // 192.168.1.5

    /* Example masks:
       - 0xFFFFFFFF  : exact match (all bits must be equal)
       - 0xFFFFFF00  : only the first 24 bits (class‑C network) matter
       - 0xFF000000  : only the first 8 bits (class‑A network) matter
    */
    uint32_t mask_list[] = {
        0xFFFFFFFF,   // exact address
        0xFFFFFF00,   // 192.168.1.0/24
        0xFF000000    // 192.0.0.0/8
    };

    bool ok = ip_matches_any_mask(ip, mask_list,
                                  sizeof(mask_list) / sizeof(mask_list[0]));

    printf("IP %u.%u.%u.%u %s any mask\n",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >>  8) & 0xFF,
           ip & 0xFF,
           ok ? "matches" : "does NOT match");

    return 0;
}
#endif
