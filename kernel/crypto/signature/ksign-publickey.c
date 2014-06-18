#include "local.h"
#include "key.h"

static int __init ksign_init(void)
{
	int rc;

	printk("ksign: Installing public key data\n");

	rc = ksign_load_keyring_from_buffer(ksign_def_public_key,
					    ksign_def_public_key_size);
	if (rc < 0)
		printk("Unable to load default keyring: error=%d\n", -rc);

	return rc;
}

module_init(ksign_init)
