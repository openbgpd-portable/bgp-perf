#include "bgpd.h"
#include "bgp.h"

int
attr_writebuf(struct ibuf *buf, uint8_t flags, uint8_t type, void *data,
    uint16_t data_len)
{
	u_char	hdr[4];

	flags &= ~ATTR_DEFMASK;
	if (data_len > 255) {
		flags |= ATTR_EXTLEN;
		hdr[2] = (data_len >> 8) & 0xff;
		hdr[3] = data_len & 0xff;
	} else {
		hdr[2] = data_len & 0xff;
	}

	hdr[0] = flags;
	hdr[1] = type;

	if (ibuf_add(buf, hdr, flags & ATTR_EXTLEN ? 4 : 3) == -1)
		return (-1);
	if (data != NULL && ibuf_add(buf, data, data_len) == -1)
		return (-1);
	return (0);
}
