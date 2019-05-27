#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>
#include <xtables.h>
#include <arpa/nameser.h>
#include <errno.h>
#include "autoconfig.h"
#include "kernel.h"
#include "xt_dns.h"
#include "xt_dns_flags.h"

#ifndef DEBUG
#define DEBUG_PRINT(fmt, ...)                                                  \
    { printf("%s(%d):" fmt, __func__, __LINE__, ##__VA_ARGS__); }
#else
#define DEBUG_PRINT(...)
#endif

#if KERNEL_VERSION >= 3
#define XT_PRINT(fmt, ...) printf(" " fmt, ##__VA_ARGS__)
#else
#define XT_PRINT(fmt, ...) printf(fmt " ", ##__VA_ARGS__)
#endif

#define O_DNS_FLAG_QR '1'
#define O_DNS_FLAG_OPCODE '2'
#define O_DNS_FLAG_AA '3'
#define O_DNS_FLAG_TC '4'
#define O_DNS_FLAG_RD '5'
#define O_DNS_FLAG_RA '6'
#define O_DNS_FLAG_AD '7'
#define O_DNS_FLAG_CD '8'
#define O_DNS_FLAG_RCODE '9'
#define O_DNS_FLAG_QNAME 'a'
#define O_DNS_FLAG_QTYPE 'b'
#define O_DNS_FLAG_RMATCH 'c'
#define O_DNS_FLAG_QNAME_MAXSIZE 'd'


static const struct option dns_opts[] = {
    {.name = "qr", .has_arg = false, .val = O_DNS_FLAG_QR},
    {.name = "opcode", .has_arg = true, .val = O_DNS_FLAG_OPCODE},
    {.name = "aa", .has_arg = false, .val = O_DNS_FLAG_AA},
    {.name = "tc", .has_arg = false, .val = O_DNS_FLAG_TC},
    {.name = "rd", .has_arg = false, .val = O_DNS_FLAG_RD},
    {.name = "ra", .has_arg = false, .val = O_DNS_FLAG_RA},
    {.name = "ad", .has_arg = false, .val = O_DNS_FLAG_AD},
    {.name = "cd", .has_arg = false, .val = O_DNS_FLAG_CD},
    {.name = "rcode", .has_arg = true, .val = O_DNS_FLAG_RCODE},
    {.name = "qname", .has_arg = true, .val = O_DNS_FLAG_QNAME},
    {.name = "qtype", .has_arg = true, .val = O_DNS_FLAG_QTYPE},
    {.name = "rmatch", .has_arg = false, .val = O_DNS_FLAG_RMATCH},
    {.name = "maxsize", .has_arg = true, .val = O_DNS_FLAG_QNAME_MAXSIZE},
    {.name = NULL, .has_arg = false},
};

static void dns_help(void) {
    printf("dns match options:\n"
           "[!] --qr match when response\n"
           "[!] --opcode match\n"
           "      (Flags QUERY,IQUERY,STATUS,NOTIFY,UPDATE)\n"
           "[!] --aa match when Authoritative Answer\n"
           "[!] --tc match when Truncated Response\n"
           "[!] --rd match when Recursion Desired\n"
           "[!] --ra match when Recursion Available\n"
           "[!] --ad match when Authentic Data\n"
           "[!] --cd match when checking Disabled\n"
           "[!] --qname\n"
           "    --rmatch set qname match mode to reverse matching flag\n"
           "[!] --qtype\n"
           "      (Flags ex. A,AAAA,MX,NS,TXT,SOA... )\n"
           "	see. "
           "http://www.iana.org/assignments/dns-parameters/"
           "dns-parameters.xhtml\n"
           "[!] --maxsize qname max size \n");
}

static void dns_init(struct xt_entry_match *m) {
    struct xt_dns *data = (struct xt_dns *)m->data;

    data->qr = data->aa = data->tc = data->rd = false;
    data->ra = data->ad = data->cd = false;

    data->opcode = 0x00;
    data->rcode = 0x00;

    data->qname[0] = 0;
    data->qname_size = 1;
    data->qtype = 0xffff;

    data->invflags = 0x0000;
    data->setflags = 0x0000;

    data->rmatch = false;
    data->maxsize = XT_DNS_MAXSIZE;
}


#ifdef KERNEL_QINGCHEN

//added by qingchen at 2019-5-9

#define NS_TYPE_ELT					0x40
#define DNS_LABELTYPE_BITSTRING		0x41

static const char digits[] = "0123456789";

static const char digitvalue[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*48*/
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /*64*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*96*/
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128*/
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*256*/
};

static int special(int ch) {
    switch (ch) {
        case 0x22: /* '"' */
        case 0x2E: /* '.' */
        case 0x3B: /* ';' */
        case 0x5C: /* '\' */
/* Special modifiers in zone files. */
        case 0x40: /* '@' */
        case 0x24: /* '$' */
            return (1);
        default:
            return (0);
    }
}


/*
 * printable(ch)
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this character visible and not a space when printed ?
 * return:
 *	boolean.
 */
static int
printable(int ch) {
    return (ch > 0x20 && ch < 0x7f);
}


static int encode_bitstring(const char **bp, const char *end,
							unsigned char **labelp,
							unsigned char ** dst,
							unsigned const char *eom)
{
	int afterslash = 0;
	const char *cp = *bp;
	unsigned char *tp;
	char c;
	const char *beg_blen;
	char *end_blen = NULL;
	int value = 0, count = 0, tbcount = 0, blen = 0;

	beg_blen = end_blen = NULL;

	/* a bitstring must contain at least 2 characters */
	if (end - cp < 2)
		return (EINVAL);

	/* XXX: currently, only hex strings are supported */
	if (*cp++ != 'x')
		return (EINVAL);
	if (!isxdigit((*cp) & 0xff)) /*%< reject '\[x/BLEN]' */
		return (EINVAL);

	for (tp = *dst + 1; cp < end && tp < eom; cp++) {
		switch((c = *cp)) {
		case ']':       /*%< end of the bitstring */
			if (afterslash) {
				if (beg_blen == NULL)
					return (EINVAL);
				blen = (int)strtol(beg_blen, &end_blen, 10);
				if (*end_blen != ']')
					return (EINVAL);
			}
			if (count)
				*tp++ = ((value << 4) & 0xff);
			cp++;   /*%< skip ']' */
			goto done;
		case '/':
			afterslash = 1;
			break;
		default:
			if (afterslash) {
				if (!isdigit(c&0xff))
					return (EINVAL);
				if (beg_blen == NULL) {

					if (c == '0') {
						/* blen never begings with 0 */
						return (EINVAL);
					}
					beg_blen = cp;
				}
			} else {
				if (!isxdigit(c&0xff))
					return (EINVAL);
				value <<= 4;
				value += digitvalue[(int)c];
				count += 4;
				tbcount += 4;
				if (tbcount > 256)
					return (EINVAL);
				if (count == 8) {
					*tp++ = value;
					count = 0;
				}
			}
			break;
		}
	}
  done:
	if (cp >= end || tp >= eom)
		return (EMSGSIZE);

	/*
	 * bit length validation:
	 * If a <length> is present, the number of digits in the <bit-data>
	 * MUST be just sufficient to contain the number of bits specified
	 * by the <length>. If there are insignificant bits in a final
	 * hexadecimal or octal digit, they MUST be zero.
	 * RFC2673, Section 3.2.
	 */
	if (blen > 0) {
		int traillen;

		if (((blen + 3) & ~3) != tbcount)
			return (EINVAL);
		traillen = tbcount - blen; /*%< between 0 and 3 */
		if (((value << (8 - traillen)) & 0xff) != 0)
			return (EINVAL);
	}
	else
		blen = tbcount;
	if (blen == 256)
		blen = 0;

	/* encode the type and the significant bit fields */
	**labelp = DNS_LABELTYPE_BITSTRING;
	**dst = blen;

	*bp = cp;
	*dst = tp;

	return (0);
}

static int ns_name_ntop(const u_char *src, char *dst, size_t dstsiz) {
    const u_char *cp;
    char *dn, *eom;
    u_char c;
    u_int n;
    cp = src;
    dn = dst;
    eom = dst + dstsiz;
    if (dn >= eom) {
        errno = EMSGSIZE;
        return (-1);
    }
    while ((n = *cp++) != 0) {
        if ((n & NS_CMPRSFLGS) != 0) {
/* Some kind of compression pointer. */
            errno = EMSGSIZE;
            return (-1);
        }
        if (dn != dst) {
            if (dn >= eom) {
                errno = EMSGSIZE;
                return (-1);
            }
            *dn++ = '.';
        }
        if (dn + n >= eom) {
            errno = EMSGSIZE;
            return (-1);
        }
        for ((void)NULL; n > 0; n--) {
            c = *cp++;
            if (special(c)) {
                if (dn + 1 >= eom) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                *dn++ = '\\';
                        *dn++ = (char)c;
            } else if (!printable(c)) {
                if (dn + 3 >= eom) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                *dn++ = '\\';
                *dn++ = digits[c/100];
                *dn++ = digits[(c % 100) / 10];
                *dn++ = digits[c % 10];
            } else {
                if (dn >= eom) {
                    errno = EMSGSIZE;
                    return (-1);
                }
                *dn++ = (char)c;
            }
        }
    }
    if (dn == dst) {
        if (dn >= eom) {
            errno = EMSGSIZE;
            return (-1);
        }
        *dn++ = '.';
    }
    if (dn >= eom) {
        errno = EMSGSIZE;
        return (-1);
    }
    *dn++ = '\0';
    return (dn - dst);
}


int ns_name_pton(const char *src, u_char *dst, size_t dstsiz)
{
	u_char *label, *bp, *eom;
	int c, n, escaped, e = 0;
	char *cp;

	escaped = 0;
	bp = dst;
	eom = dst + dstsiz;
	label = bp++;

	while ((c = *src++) != 0) {
		if (escaped) {
			if (c == '[') { /*%< start a bit string label */
				if ((cp = strchr(src, ']')) == NULL) {
					errno = EINVAL; /*%< ??? */
					return (-1);
				}
				if ((e = encode_bitstring(&src, cp + 2,
							 &label, &bp, eom))
				    != 0) {
					errno = e;
					return (-1);
				}
				escaped = 0;
				label = bp++;
				if ((c = *src++) == 0)
					goto done;
				else if (c != '.') {
					errno = EINVAL;
					return  (-1);
				}
				continue;
			}
			else if ((cp = strchr(digits, c)) != NULL) {
				n = (cp - digits) * 100;
				if ((c = *src++) == 0 ||
				    (cp = strchr(digits, c)) == NULL) {
					errno = EMSGSIZE;
					return (-1);
				}
				n += (cp - digits) * 10;
				if ((c = *src++) == 0 ||
				    (cp = strchr(digits, c)) == NULL) {
					errno = EMSGSIZE;
					return (-1);
				}
				n += (cp - digits);
				if (n > 255) {
					errno = EMSGSIZE;
					return (-1);
				}
				c = n;
			}
			escaped = 0;
		} else if (c == '\\') {
			escaped = 1;
			continue;
		} else if (c == '.') {
			c = (bp - label - 1);
			if ((c & NS_CMPRSFLGS) != 0) {  /*%< Label too big. */
				errno = EMSGSIZE;
				return (-1);
			}
			if (label >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			*label = c;
			/* Fully qualified ? */
			if (*src == '\0') {
				if (c != 0) {
					if (bp >= eom) {
						errno = EMSGSIZE;
						return (-1);
					}
					*bp++ = '\0';
				}
				if ((bp - dst) > MAXCDNAME) {
					errno = EMSGSIZE;
					return (-1);
				}

				return (1);
			}
			if (c == 0 || *src == '.') {
				errno = EMSGSIZE;
				return (-1);
			}
			label = bp++;
			continue;
		}
		if (bp >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*bp++ = (u_char)c;
	}
	c = (bp - label - 1);
	if ((c & NS_CMPRSFLGS) != 0) {	  /*%< Label too big. */
		errno = EMSGSIZE;
		return (-1);
	}
  done:
	if (label >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*label = c;
	if (c != 0) {
		if (bp >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*bp++ = 0;
	}
	if ((bp - dst) > MAXCDNAME) {   /*%< src too big */
		errno = EMSGSIZE;
		return (-1);
	}

	return (0);
}

static int labellen(const unsigned char *lp)
{
	int bitlen;
	unsigned char l = *lp;

	if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
		/* should be avoided by the caller */
		return -1;
	}

	if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
		if (l == DNS_LABELTYPE_BITSTRING) {
			if ((bitlen = *(lp + 1)) == 0)
				bitlen = 256;
			return ((bitlen + 7 ) / 8 + 1);
		}

		return -1;    /*%< unknwon ELT */
	}

	return l;
}

static int mklower(int ch)
{
	if (ch >= 0x41 && ch <= 0x5A)
		return (ch + 0x20);

	return (ch);
}

static int dn_find(const unsigned char *domain,
				   const unsigned char *msg,
				   const unsigned char * const *dnptrs,
				   const unsigned char * const *lastdnptr)
{
	const unsigned char *dn, *cp, *sp;
	const unsigned char * const *cpp;
	u_int n;

	for (cpp = dnptrs; cpp < lastdnptr; cpp++) {
		sp = *cpp;
		/*
		 * terminate search on:
		 * root label
		 * compression pointer
		 * unusable offset
		 */
		while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 &&
				(sp - msg) < 0x4000) {
			dn = domain;
			cp = sp;

			while ((n = *cp++) != 0) {
				/*
				 * check for indirection
				 */
				switch (n & NS_CMPRSFLGS) {
				case 0:	 /*%< normal case, n == len */
					n = labellen(cp - 1); /*%< XXX */
					if (n != *dn++)
						goto next;

					for (; n > 0; n--)
						if (mklower(*dn++) !=
						    mklower(*cp++))
							goto next;
					/* Is next root for both ? */
					if (*dn == '\0' && *cp == '\0')
						return (sp - msg);
					if (*dn)
						continue;
					goto next;
				case NS_CMPRSFLGS:      /*%< indirection */
					cp = msg + (((n & 0x3f) << 8) | *cp);
					break;

				default:	/*%< illegal type */
					errno = EMSGSIZE;
					return -1;
				}
			}
next:
			sp += *sp + 1;
		}
	}

	errno = ENOENT;
	return -1;
}

int ns_name_pack(const unsigned char *src,
				 unsigned char *dst, int dstsiz,
				 const unsigned char **dnptrs,
				 const unsigned char **lastdnptr)
{
	unsigned char *dstp;
	const unsigned char **cpp, **lpp, *eob, *msg;
	const unsigned char *srcp;
	int n, l, first = 1;

	srcp = src;
	dstp = dst;
	eob = dstp + dstsiz;
	lpp = cpp = NULL;

	if (dnptrs != NULL) {
		if ((msg = *dnptrs++) != NULL) {
			for (cpp = dnptrs; *cpp != NULL; cpp++)
				continue;

			lpp = cpp;      /*%< end of list to search */
		}
	} else {
		msg = NULL;
	}

	/* make sure the domain we are about to add is legal */
	l = 0;
	do {
		int l0;

		n = *srcp;
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			errno = EMSGSIZE;
			return -1;
		}

		if ((l0 = labellen(srcp)) < 0) {
			errno = EINVAL;
			return -1;
		}

		l += l0 + 1;
		if (l > MAXCDNAME) {
			errno = EMSGSIZE;
			return -1;
		}

		srcp += l0 + 1;
	} while (n != 0);

	/* from here on we need to reset compression pointer array on error */
	srcp = src;

	do {
		/* Look to see if we can use pointers. */
		n = *srcp;

		if (n != 0 && msg != NULL) {
			l = dn_find(srcp, msg, (const unsigned char * const *) dnptrs,
						(const unsigned char * const *) lpp);
			if (l >= 0) {
				if (dstp + 1 >= eob) {
					goto cleanup;
				}

				*dstp++ = ((u_int32_t)l >> 8) | NS_CMPRSFLGS;
				*dstp++ = l % 256;
				return (dstp - dst);
			}

			/* Not found, save it. */
			if (lastdnptr != NULL && cpp < lastdnptr - 1 &&
				(dstp - msg) < 0x4000 && first) {
				*cpp++ = dstp;
				*cpp = NULL;
				first = 0;
			}
		}

		/* copy label to buffer */
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Should not happen. */
			goto cleanup;
		}

		n = labellen(srcp);
		if (dstp + 1 + n >= eob) {
			goto cleanup;
		}

		memcpy(dstp, srcp, (size_t)(n + 1));
		srcp += n + 1;
		dstp += n + 1;
	} while (n != 0);

	if (dstp > eob) {
cleanup:
		if (msg != NULL)
			*lpp = NULL;

			errno = EMSGSIZE;
			return -1;
	}

	return dstp - dst;
}

int ns_name_compress(const char *src,
					 unsigned char *dst, size_t dstsiz,
					 const unsigned char **dnptrs,
					 const unsigned char **lastdnptr)
{
	unsigned char tmp[NS_MAXCDNAME];

	if (ns_name_pton(src, tmp, sizeof(tmp)) == -1)
		return -1;

	return ns_name_pack(tmp, dst, dstsiz, dnptrs, lastdnptr);
}
/////////////////////////////////////////////////////////////////////////

#endif

static uint16_t parse_code_flag(const char *name, const char *flag,
                                const struct dns_flag_names *codes) {
    uint16_t i;
    uint16_t ret = 0;
    for (i = 0; codes[i].name != NULL; i++) {
        if (strcasecmp(codes[i].name, flag) == 0) {
            ret = codes[i].flag;
            break;
        }
    }
    if (codes[i].name == NULL) {
        xtables_error(PARAMETER_PROBLEM, "Unknown %s `%s'", name, flag);
    }
    return ret;
}

#define parse_opcode_flags(flag)                                               \
    parse_code_flag("OPCODE", flag, dns_flag_opcode)
#define parse_rcode_flags(flag) parse_code_flag("RCODE", flag, dns_flag_rcode)
#define parse_qtype_flags(flag) parse_code_flag("QTYPE", flag, dns_flag_qtype)

static void parse_qname(const char *flag, uint8_t *qname) {
    char buffer[XT_DNS_MAXSIZE];
    char *fp;
    fp = buffer;
    while (*flag != '\0') {
        *fp++ = tolower(*flag++);
    }
    *fp = '\0';
    if (ns_name_pton(buffer, qname, XT_DNS_MAXSIZE)) {
        xtables_error(PARAMETER_PROBLEM, "Invalid qname %s '%s'", flag, qname);
    }
}
static int qname_size(const uint8_t *qname) {
    uint8_t len = 0;
    uint8_t llen = 255;
    while (llen != 0 && len < XT_DNS_MAXSIZE) {
        llen = *(qname + len);
        len += llen + 1;
    }
    return len;
}

static int dns_parse(int c, char **argv, int invert, unsigned int *flags,
                     const void *entry, struct xt_entry_match **match) {
    struct xt_dns *data = (struct xt_dns *)(*match)->data;

    switch (c) {
    case O_DNS_FLAG_QR:
        if (*flags & XT_DNS_FLAG_QR) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--qr' allowed");
        }
        data->qr = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_QR;
        }
        *flags |= XT_DNS_FLAG_QR;
        break;
    case O_DNS_FLAG_OPCODE:
        if (*flags & XT_DNS_FLAG_OPCODE) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--opcode' allowed");
        }
        data->opcode = parse_opcode_flags(optarg);
        data->setflags |= XT_DNS_FLAG_OPCODE;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_OPCODE;
        }
        *flags |= XT_DNS_FLAG_OPCODE;
        break;
    case O_DNS_FLAG_AA:
        if (*flags & XT_DNS_FLAG_AA) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--aa' allowed");
        }
        data->aa = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_AA;
        }
        *flags |= XT_DNS_FLAG_AA;
        break;
    case O_DNS_FLAG_TC:
        if (*flags & XT_DNS_FLAG_TC) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--tc' allowed");
        }
        data->tc = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_TC;
        }
        *flags |= XT_DNS_FLAG_TC;
        break;
    case O_DNS_FLAG_RD:
        if (*flags & XT_DNS_FLAG_RD) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--rd' allowed");
        }
        data->rd = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_RD;
        }
        *flags |= XT_DNS_FLAG_RD;
        break;
    case O_DNS_FLAG_RA:
        if (*flags & XT_DNS_FLAG_RA) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--ra' allowed");
        }
        data->ra = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_RA;
        }
        *flags |= XT_DNS_FLAG_RA;
        break;
    case O_DNS_FLAG_AD:
        if (*flags & XT_DNS_FLAG_AD) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--ad' allowed");
        }
        data->ad = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_AD;
        }
        *flags |= XT_DNS_FLAG_AD;
        break;
    case O_DNS_FLAG_CD:
        if (*flags & XT_DNS_FLAG_CD) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--cd' allowed");
        }
        data->cd = true;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_CD;
        }
        *flags |= XT_DNS_FLAG_CD;
        break;
    case O_DNS_FLAG_RCODE:
        if (*flags & XT_DNS_FLAG_RCODE) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--rcode' allowed");
        }
        data->rcode = parse_rcode_flags(optarg);
        data->setflags |= XT_DNS_FLAG_RCODE;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_RCODE;
        }
        *flags |= XT_DNS_FLAG_RCODE;
        break;
    case O_DNS_FLAG_QNAME:
        if (*flags & XT_DNS_FLAG_QNAME) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--qname' allowed");
        }
        parse_qname(optarg, data->qname);
        data->qname_size = qname_size(data->qname);
        data->setflags |= XT_DNS_FLAG_QNAME;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_QNAME;
        }
        *flags |= XT_DNS_FLAG_QNAME;
        break;
    case O_DNS_FLAG_QTYPE:
        if (*flags & XT_DNS_FLAG_QTYPE) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--qtype' allowed");
        }
        data->qtype = htons(parse_qtype_flags(optarg));
        data->setflags |= XT_DNS_FLAG_QTYPE;
        if (invert) {
            data->invflags |= XT_DNS_FLAG_QTYPE;
        }
        *flags |= XT_DNS_FLAG_QTYPE;
        break;
    case O_DNS_FLAG_RMATCH:
        if (*flags & XT_DNS_FLAG_RMATCH) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--rmatch' allowed");
        }
        data->rmatch = true;
        if (invert) {
            xtables_error(PARAMETER_PROBLEM, "can't set invert `--rmatch' ");
        }
        *flags |= XT_DNS_FLAG_RMATCH;
        break;
    case O_DNS_FLAG_QNAME_MAXSIZE:
        if (*flags & XT_DNS_FLAG_QNAME_MAXSIZE) {
            xtables_error(PARAMETER_PROBLEM, "Only one `--maxsize' allowed");
        }
        data->maxsize = atoi(optarg);
        if (invert) {
            data->invflags |= XT_DNS_FLAG_QNAME_MAXSIZE;
        }
        *flags |= XT_DNS_FLAG_QNAME_MAXSIZE;
        break;

    default:
        return 0;
    }
    return 1;
}

static void print_flag(const char *name, bool value, uint16_t mask, uint16_t invflag) {
    if (value) {
        if (mask & invflag) {
            XT_PRINT("!");
        }
        XT_PRINT("--%s", name);
    }
}
static void print_flag_attribute(const char *name, uint16_t value,
                                 uint16_t mask, uint16_t setflags,
                                 uint16_t invflag,
                                 const struct dns_flag_names *codes) {
    int i = 0;
    if (mask & setflags) {
        if (mask & invflag) {
            XT_PRINT("!");
        }
        for (i = 0; codes[i].name != NULL; i++) {
            if (codes[i].flag == value) {
                break;
            }
        }
        if (codes[i].name == NULL) {
            xtables_error(PARAMETER_PROBLEM, "Unknown %s `%d'", name, value);
        }
        XT_PRINT("--%s %s", name, codes[i].name);
    }
}

#define print_flag_opcode(value, setflags, invflags)                           \
    print_flag_attribute("opcode", value, XT_DNS_FLAG_OPCODE, setflags,        \
                         invflags, dns_flag_opcode)
#define print_flag_rcode(value, setflags, invflags)                            \
    print_flag_attribute("rcode", value, XT_DNS_FLAG_RCODE, setflags,          \
                         invflags, dns_flag_rcode)
#define print_flag_qtype(value, setflags, invflags)                            \
    print_flag_attribute("qtype", value, XT_DNS_FLAG_QTYPE, setflags,          \
                         invflags, dns_flag_qtype)

static void print_flag_qname(const u_char *qname, uint16_t setflags, uint16_t invflag) {
    char tmp[XT_DNS_MAXSIZE];
    if (XT_DNS_FLAG_QNAME & setflags) {
        if (XT_DNS_FLAG_QNAME & invflag) {
            XT_PRINT("!");
        }
        if (ns_name_ntop(qname, tmp, sizeof(tmp)) == -1)
            xtables_error(PARAMETER_PROBLEM, "Unknown qname %s\n", tmp);
        XT_PRINT("--qname %s", tmp);
    }
}
static void print_maxsize(uint8_t maxsize, uint16_t invflag) {
    if (maxsize != XT_DNS_MAXSIZE) {
        if (XT_DNS_FLAG_QNAME_MAXSIZE & invflag) {
            XT_PRINT("!");
        }
        XT_PRINT("--maxsize %d", maxsize);
    }
}

static void dns_dump(const void *ip, const struct xt_entry_match *match) {
    const struct xt_dns *dns = (struct xt_dns *)match->data;
    print_flag("qr", dns->qr, XT_DNS_FLAG_QR, dns->invflags);
    print_flag_opcode(dns->opcode, dns->setflags, dns->invflags);
    print_flag("aa", dns->aa, XT_DNS_FLAG_AA, dns->invflags);
    print_flag("tc", dns->tc, XT_DNS_FLAG_TC, dns->invflags);
    print_flag("rd", dns->rd, XT_DNS_FLAG_RD, dns->invflags);
    print_flag("ra", dns->ra, XT_DNS_FLAG_RA, dns->invflags);
    print_flag("ad", dns->ad, XT_DNS_FLAG_AD, dns->invflags);
    print_flag("cd", dns->cd, XT_DNS_FLAG_CD, dns->invflags);
    print_flag_rcode(dns->rcode, dns->setflags, dns->invflags);
    print_flag_qname(dns->qname, dns->setflags, dns->invflags);
    print_flag_qtype(ntohs(dns->qtype), dns->setflags, dns->invflags);
    print_flag("rmatch", dns->rmatch, XT_DNS_FLAG_RMATCH, dns->invflags);
    print_maxsize(dns->maxsize, dns->invflags);
}

static void dns_print(const void *ip, const struct xt_entry_match *match,
                      int numeric) {
    XT_PRINT("dns");
    dns_dump(ip, match);
}

static void dns_save(const void *ip, const struct xt_entry_match *match) {
    dns_dump(ip, match);
}

static struct xtables_match dns_match = {
    .family = NFPROTO_UNSPEC,
    .name = "dns",
    .version = XTABLES_VERSION,
    .size = XT_ALIGN(sizeof(struct xt_dns)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_dns)),
    .help = dns_help,
    .init = dns_init,
    .parse = dns_parse,
    .print = dns_print,
    .save = dns_save,
    .extra_opts = dns_opts,
};

void _init(void) {
    xtables_register_match(&dns_match);
}
