#include <edhoc.h>
#include <zephyr/sys/printk.h>

int main(void)
{
	struct edhoc_context ctx;
	int ret;

	ret = edhoc_context_init(&ctx);
	if (ret == EDHOC_SUCCESS) {
		printk("context init success\n");
	} else {
		printk("context init failed: %d\n", ret);
	}

	return 0;
}

