#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

#include "chameleon.h"

int itls_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

struct proto itls = {
		.name			= "ITLS",
		.connect	    = itls_connect,
		.obj_size		= sizeof(struct sock),
};

int itls_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int res = 0;

	lock_sock(sk);
	printk("And here is itls connect\n");
	release_sock(sk);
	return res;
}
EXPORT_SYMBOL(itls_connect);

/*
 * proto_ops region
 */

int chameleon_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	int err = 0;
	struct sock *sk = sock->sk;

	sock->state = SS_CONNECTED;

	err = sk->sk_prot->connect(sk, uaddr, addr_len);
	printk("One would say \"Iam connected\"\n");
	return err;
}
EXPORT_SYMBOL(chameleon_stream_connect);

int chameleon_release(struct socket *sock)
{
	printk("Release chameleon socket\n");
	return 0;
}
EXPORT_SYMBOL(chameleon_release);


const struct proto_ops chameleon_stream_ops = {
	.family		= AF_CHMLN,
	.owner		= THIS_MODULE,
	.connect	= chameleon_stream_connect,
	.release	= chameleon_release,
};

/*
 * net_proto_family region
 */

static int chameleon_create(struct net *net,
		      struct socket *sock,
		      int protocol,
		      int kern)
{
	struct sock *sk;

	sock->ops = &chameleon_stream_ops;

	sk = sk_alloc(net, AF_CHMLN, GFP_KERNEL, &itls, kern);
	if (!sk)
		goto error;

	sock_init_data(sock, sk);

	printk("Create chameleon socket\n");
	return 0;
error:
	return -1;
}

static const struct net_proto_family chmln_family = {
		.family		= AF_CHMLN,
		.create 	= chameleon_create,
		.owner  	= THIS_MODULE,
};

/*
 * module initialization
 */

static int __init
chameleon_go(void)
{
	printk(KERN_INFO"CHAMELEON PROTO: start\n");
	(void)sock_register(&chmln_family);
	return 0;
}

static void __exit
chameleon_stop(void)
{
	sock_unregister(AF_CHMLN);
	printk(KERN_INFO"CHAMELEON PROTO: stop\n");
}

module_init(chameleon_go);
module_exit(chameleon_stop);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arek Kusztal");
