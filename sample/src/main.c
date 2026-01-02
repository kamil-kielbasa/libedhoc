#include <zephyr/kernel.h>
#include <edhoc.h>

int main(void)
{
	struct edhoc_context ctx;
	int ret;

	ret = edhoc_context_init(&ctx);
	if (ret == EDHOC_SUCCESS) {
		printk("libedhoc: context init success\n");
	} else {
		printk("libedhoc: context init failed: %d\n", ret);
	}

	return 0;
}

