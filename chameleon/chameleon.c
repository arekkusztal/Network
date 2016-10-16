#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>

#include "chameleon.h"

#define UDP_INC_STATS(net, field, is_udplite)		      do { \
	if (is_udplite) SNMP_INC_STATS((net)->mib.udplite_statistics, field);       \
	else		SNMP_INC_STATS((net)->mib.udp_statistics, field);  }  while(0)

extern void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst);

static void dump_udp(struct sk_buff *skb, int arg)
{
	/*
	 * Here skb should be created so dump it
	 *
	 */
	printk("------------------ <<< %d >>> ------------------\n", arg);

	printk("SKB(udp_sendmsg)\n");

	print_hex_dump(KERN_INFO, "skb 1:", DUMP_PREFIX_ADDRESS,
			16, 1, skb, sizeof(*skb), true);

	printk("next:\t%p\n",skb->next);
	printk("prev:\t%p\n",skb->prev);
	printk("sk:\t%p\n",skb->sk);
	printk("dev:\t%p\n",skb->dev);
	printk("len:\t%d\n",skb->len);
	printk("data len:\t%d",skb->data_len);
	printk("len:\t%hu\n",skb->mac_len);
	printk("len:\t%hu\n",skb->hdr_len);
	printk("FLAGS(cloned): %hu\n",(unsigned short)(unsigned char)skb->cloned);
	printk("FLAGS(cloned): %hu\n",(unsigned short)(unsigned char)skb->cloned);
	printk("FLAGS(cloned): %hu\n",(unsigned short)(unsigned char)skb->cloned);
	printk("FLAGS(__pkt_type_offset[0]): %hu\n",(unsigned short)(unsigned char)skb->__pkt_type_offset[0]);
	printk("FLAGS(__pkt_type_offset[1]): %hu\n",(unsigned short)(unsigned char)skb->__pkt_type_offset[1]);
	printk("FLAGS(__pkt_type_offset[2]): %hu\n",(unsigned short)(unsigned char)skb->__pkt_type_offset[2]);
	printk("FLAGS(__pkt_type_offset[3]): %hu\n",(unsigned short)(unsigned char)skb->__pkt_type_offset[3]);
	printk("priority:\t%u\n",skb->priority);
	printk("skb_iif:\t%d\n",skb->skb_iif);
	printk("hash:\t%u\n",skb->hash);
	printk("vlan_proto:\t%hu\n",htons(skb->vlan_proto));
	printk("vlan_tci:\t%hu\n",skb->vlan_tci);
	printk("reserved_tailroom:\t%u\n",skb->reserved_tailroom);
	printk("inner_protocol:\t%hu\n",skb->inner_protocol);
	printk("inner_transport_header:\t%hu\n",skb->inner_transport_header);
	printk("inner_network_header:\t%hu\n",skb->inner_network_header);
	printk("inner_mac_header:\t%hu\n",skb->inner_mac_header);
	printk("protocol:\t%hu\n",htons(skb->protocol));
	printk("transport_header:\t%hu\n",htons(skb->transport_header));
	printk("network_header:\t%hu\n",htons(skb->network_header));
	printk("mac_header:\t%hu\n",htons(skb->mac_header));


	char *transport;
	transport = (char*)skb + skb_transport_offset(skb);

	printk("transport:\t %p\n",transport);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	printk("tail:\t %d\n",skb->tail);
	printk("end:\t %d\n",skb->end);
#endif
	printk("head:\t %p\n",skb->head);
	printk("data:\t %p\n",skb->data);

	print_hex_dump(KERN_INFO, "udp:", DUMP_PREFIX_ADDRESS,
			16, 1, transport, 32, true);

	print_hex_dump(KERN_INFO, "udp data:", DUMP_PREFIX_ADDRESS,
			16, 1, skb->data, skb->tail, true);

	printk("------------------------------------\n");
}


static int udp_send_skb_2(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;

	dump_udp(skb,1);
	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	if (is_udplite)  				 /*     UDP-Lite      */
		csum = udplite_csum(skb);

	else if (sk->sk_no_check_tx) {   /* UDP csum disabled */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	/*
	 * dump sk and skb
	 */


	dump_udp(skb,2);
	skb->data[32] = 1;
	err = ip_send_skb(sock_net(sk), skb);
	printk("ip_send_skb output = %d", err);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}
extern int udp_push_pending_frames(struct sock *sk);
int udp_sendmsg_2(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;

	printk("UDP: Now i am in the module xP\n");

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;

	getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}

	ipc.sockc.tsflags = sk->sk_tsflags;
	ipc.addr = inet->inet_saddr;
	ipc.oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sk, msg, &ipc, sk->sk_family == AF_INET6);
		if (unlikely(err)) {
			kfree(ipc.opt);
			return err;
		}
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	sock_tx_timestamp(sk, ipc.sockc.tsflags, &ipc.tx_flags);

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);
	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;

		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport);

		if (!saddr && ipc.oif) {
			err = l3mdev_get_saddr(net, ipc.oif, fl4);
			if (err < 0)
				goto out;
		}

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}
		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:
	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  msg->msg_flags);
		err = PTR_ERR(skb);





		if (!IS_ERR_OR_NULL(skb))
			err = udp_send_skb_2(skb, fl4);
		goto out;
	}
	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited("cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}






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
	int err = udp_sendmsg_2(sk, msg, len);
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

	//printk("dest addr = %d",(int)usin->sin_addr.s_addr);
	daddr = usin->sin_addr.s_addr;
	dport = usin->sin_port;
	if (dport == 0)
		return -EINVAL;

	err = udp_sendmsg(sk, &msg, 64);
	//printk("MESSAGE %d\n", err);

	//lock_sock(sk);
	//printk("And here is itls connect\n");

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
	//printk("One would say \"Iam connected\"\n");
	return err;
}
EXPORT_SYMBOL(chameleon_stream_connect);

int chameleon_release(struct socket *sock)
{
	printk("Release chameleon socket\n\n"
			"============================================"
			"\n\n");
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

	printk("Create chameleon socket\n\n"
			"============================================"
			"\n\n");
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
