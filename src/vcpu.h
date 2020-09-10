#ifndef __VCPU_H__
#define __VCPU_H__

#pragma pack (1)

  typedef struct
  {
    __u16     limit_lo;         /* Bits  0 - 15  Limit low bits      */
    unsigned base_lo     : 24; /* Bits 16 - 39  Base low bits       */
    unsigned type        : 4;  /* Bits 40 - 43  Segment type        */
    unsigned s           : 1;  /* Bits 44       System/user descriptor   */
    unsigned privilege   : 2;  /* Bits 45 - 46  Segment privilege   */
    unsigned present     : 1;  /* Bit  47       Segment is present? */
    unsigned limit_hi    : 4;  /* Bits 48 - 51  Limit high bits     */
    unsigned available   : 1;  /* Bit  52       Available to OS use */
    unsigned zero        : 1;  /* Bit  53       Always 0            */
    unsigned bits_32     : 1;  /* Bit  54       32-Bit segment      */
    unsigned granularity : 1;  /* Bit  55       Page granularity    */
    unsigned base_hi     : 8;  /* Bits 56 - 63  Base high bits      */

  } descriptor_t;

#pragma pack ()  

#endif
