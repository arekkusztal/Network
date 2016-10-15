#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>


#include "chameleon.h"

static void send(void)
{
/*	struct ethhdr *eth;
	struct sk_buff *skb;
	struct udphdr *udph;
	struct iphdr *iph;
	uint16_t udp_len = 16;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb)
	        return;

	skb_put(skb, len);

	skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph = udp_hdr(skb);
	udph->source = htons(1234);
	udph->dest = htons(1235));
	udph->len = htons(udp_len);
	udph->check = 0;
	udph->check = csum_tcpudp_magic(local_ip,
	                                remote_ip,
	                                udp_len, IPPROTO_UDP,
	                                csum_partial(udph, udp_len, 0));

	if (udph->check == 0)
	        udph->check = CSUM_MANGLED_0;

	skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

	put_unaligned(0x45, (unsigned char *)iph);
	iph->tos      = 0;
	put_unaligned(htons(ip_len), &(iph->tot_len));
	iph->id       = htons(atomic_inc_return(&ip_ident));
	iph->frag_off = 0;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check    = 0;
	put_unaligned(local_ip, &(iph->saddr));
	put_unaligned(remote_ip, &(iph->daddr));
	iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);

	eth = (struct ethhdr *) skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb->protocol = eth->h_proto = htons(ETH_P_IP);
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, remote_mac, ETH_ALEN);

	skb->dev = dev;


	dev_queue_xmit(skb); */
}


extern void itls_init_sock_internal(struct sock *sk);
extern int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int int17_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
static int itls_init_sock(struct sock *sk);
int itls_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
extern const struct inet_connection_sock_af_ops ipv4_specific;
struct proto itls = {
		.name			= "INT17",
		.init 			= itls_init_sock,
		.sendmsg 		= int17_sendmsg,
		.connect	    = itls_connect,
		.obj_size		= sizeof(struct tcp_sock),
};

int int17_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	printk("int17 sendmsg\n");
	int err = udp_sendmsg(sk, msg, len);
	printk("error = %d\n",err);
	return 0;
}


static int itls_init_sock(struct sock *sk)
{

	struct inet_connection_sock *icsk = inet_csk(sk);

	printk("INIT ME\n");

	itls_init_sock_internal(sk);

	icsk->icsk_af_ops = &ipv4_specific;
	return 0;
}

extern int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);

int itls_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int err = 0;
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct flowi4 *fl4;
	struct rtable *rt;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	struct msghdr msg = {	.msg_flags = MSG_MORE };

	msg.msg_name = usin;
	msg.msg_namelen = sizeof(*usin);

	fl4 = &inet->cork.fl.u.ip4;

	printk("dest addr = %d",(int)usin->sin_addr.s_addr);
	daddr = usin->sin_addr.s_addr;
	dport = usin->sin_port;
	if (dport == 0)
		return -EINVAL;

	err = udp_sendmsg(sk, &msg, 64);
	printk("MESSAGE %d\n", err);

	//lock_sock(sk);
	printk("And here is itls connect\n");

	//release_sock(sk);
	return err;
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

int chameleon_sendmsg(struct socket *sk, struct msghdr *msg, size_t len);
const struct proto_ops chameleon_stream_ops = {
	.family		= AF_CHMLN,
	.owner		= THIS_MODULE,
	.connect	= chameleon_stream_connect,
	.release	= chameleon_release,
	.sendmsg 	= chameleon_sendmsg
};



/*
 * net_proto_family region
 */

int chameleon_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{

	int err = 0;
	struct sock *sk = sock->sk;
	if (sk->sk_prot->sendmsg) {
		err = sk->sk_prot->sendmsg(sk, msg, len);
		if (err)
			sk_common_release(sk);
	}
	return 0;
}

static int chameleon_create(struct net *net,
		      struct socket *sock,
		      int protocol,
		      int kern)
{
	int err = 0;
	struct sock *sk;

	sock->ops = &chameleon_stream_ops;

	sk = sk_alloc(net, AF_CHMLN, GFP_KERNEL, &itls, kern);
	if (!sk)
		goto error;

	sock_init_data(sock, sk);

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			sk_common_release(sk);
	}

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
