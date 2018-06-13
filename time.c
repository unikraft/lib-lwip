#include <uk/arch/time.h>
#include <uk/plat/time.h>
#include <lwip/sys.h>

u32_t sys_now(void)
{
	return (u32_t) ukarch_time_nsec_to_msec(ukplat_monotonic_clock());
}
