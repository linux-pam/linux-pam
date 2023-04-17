#include <inttypes.h>

typedef uint64_t usec_t;

#define PRI_USEC PRIu64
#define USEC_FMT "%" PRI_USEC

#define USEC_INFINITY ((usec_t) UINT64_MAX)

#define USEC_PER_SEC  ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)

#define USEC_PER_MINUTE ((usec_t) (60ULL*USEC_PER_SEC))
#define USEC_PER_HOUR ((usec_t) (60ULL*USEC_PER_MINUTE))
#define USEC_PER_DAY ((usec_t) (24ULL*USEC_PER_HOUR))
#define USEC_PER_WEEK ((usec_t) (7ULL*USEC_PER_DAY))
#define USEC_PER_MONTH ((usec_t) (2629800ULL*USEC_PER_SEC))
#define USEC_PER_YEAR ((usec_t) (31557600ULL*USEC_PER_SEC))

#define FORMAT_TIMESPAN_MAX 64U

int parse_time(const char *t, usec_t *ret, usec_t default_unit);
char* format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy)
	__attribute__((__warn_unused_result__));
