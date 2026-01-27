#include <zephyr/kernel.h>
#include <edhoc.h>

int main(void)
{
	struct edhoc_context ctx;
	int ret;

	ret = edhoc_context_init(&ctx);
	if (ret == EDHOC_SUCCESS) {
		EDHOC_LOG_INF("context init success\n");
	} else {
		EDHOC_LOG_INF("context init failed: %d\n", ret);
	}

	return 0;
}

