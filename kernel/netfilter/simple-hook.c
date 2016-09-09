#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/version.h>

static struct nf_hook_ops n_hook;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
unsigned int hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int (*f)(struct sk_buff *))
{
    struct net_device *dev = skb->dev;
    printk("\ndev.name = %s", dev->name);
    printk("\nHooked");
    return 0;
}
#else
unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    printk("\nHooked");
    return 0;
}
#endif

static int __init
start_module(void)
{
    n_hook.hook = hook_func;
    n_hook.hooknum = 0; //NF_IP_PRE_ROUTIING
    n_hook.pf = PF_INET;
    n_hook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&n_hook);

    return 0;
}

static void __exit
exit_module(void)
{
    nf_unregister_hook(&n_hook);
}

module_init(start_module);
module_exit(exit_module);

MODULE_LICENSE("GPL");

