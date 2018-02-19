#include <linux/module.h>
#include <linux/slab.h>

MODULE_AUTHOR("TACIXAT");
MODULE_DESCRIPTION("Jazelle kernel module.");
MODULE_LICENSE("PROPRIETARY");

extern int hwkm_entry_point(void *table_space);
extern void hwkm_exit_point(void);

int 
wrapper_init(void)
{
	void *table_space = kmalloc(0x500 * 4, GFP_KERNEL);
	return hwkm_entry_point(table_space);
	kfree(table_space);
}

void
wrapper_exit(void)
{
	return hwkm_exit_point();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

