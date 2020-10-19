#ifndef X_WIN_BIN_STRUCT_H
#define X_WIN_BIN_STRUCT_H

#include <xwinbin/compiler.h>
#include <stdint.h>
#include <stddef.h>


static FORCE_INLINE
int8_t
struct_read_s8(const uint8_t *buf, size_t *off)
{
    return ((int8_t *)buf)[(*off)++];
}


static FORCE_INLINE
uint8_t
struct_read_u8(const uint8_t *buf, size_t *off)
{
    return buf[(*off)++];
}


static FORCE_INLINE
char
struct_read_char(const uint8_t *buf, size_t *off)
{
    return ((char *)buf)[(*off)++];
}


static FORCE_INLINE
uint16_t
struct_read_u16_le(const uint8_t *buf, size_t *off)
{
    const uint8_t  *bufptr = &buf[*off];
    uint16_t        ret;

    /* Endianness-invariant read of little-endian data */
    ret = (
      ((uint16_t)bufptr[0]) |
      ((uint16_t)bufptr[1] << (8 * 1))
    );

    *off += 2;
    return ret;
}


static FORCE_INLINE
uint32_t
struct_read_u32_le(const uint8_t *buf, size_t *off)
{
    const uint8_t  *bufptr = &buf[*off];
    uint32_t        ret;


    /* Endianness-invariant read of little-endian data */
    ret = (
      ((uint32_t)bufptr[0]) |
      ((uint32_t)bufptr[1] << (8 * 1)) |
      ((uint32_t)bufptr[2] << (8 * 2)) |
      ((uint32_t)bufptr[3] << (8 * 3))
    );

    *off += 4;
    return ret;
}


static FORCE_INLINE
uint64_t
struct_read_u64_le(const uint8_t *buf, size_t *off)
{
    const uint8_t  *bufptr = &buf[*off];
    uint64_t        ret;

    /* Endianness-invariant read of little-endian data */
    ret = (
      ((uint64_t)bufptr[0]) |
      ((uint64_t)bufptr[1] << (8 * 1)) |
      ((uint64_t)bufptr[2] << (8 * 2)) |
      ((uint64_t)bufptr[3] << (8 * 3)) |
      ((uint64_t)bufptr[4] << (8 * 4)) |
      ((uint64_t)bufptr[5] << (8 * 5)) |
      ((uint64_t)bufptr[6] << (8 * 6)) |
      ((uint64_t)bufptr[7] << (8 * 7))
    );

    *off += 8;
    return ret;
}


static FORCE_INLINE
int
struct_probe(size_t off, size_t probe_size, size_t off_limit)
{
    if (off > off_limit)
    {
        return 0;
    }

    if (off + probe_size > off_limit)
    {
        return 0;
    }

    return 1;
}

#endif /* X_WIN_BIN_STRUCT_H */
