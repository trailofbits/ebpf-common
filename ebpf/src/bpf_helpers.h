/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <string>

namespace tob::ebpf {

// clang-format off
const std::string kBPFHelperDefinitions{R"src(
struct sk_msg_buff;
struct bpf_dynptr;
struct bpf_pidns_info;
struct btf_ptr;
struct bpf_redir_neigh;
struct bpf_timer;

typedef void *(*bpf_map_lookup_elem_t)(struct bpf_map *map, const void *key);
static bpf_map_lookup_elem_t bpf_map_lookup_elem = (bpf_map_lookup_elem_t) 1;

typedef long (*bpf_map_update_elem_t)(struct bpf_map *map, const void *key, const void *value, u64 flags);
static bpf_map_update_elem_t bpf_map_update_elem = (bpf_map_update_elem_t) 2;

typedef long (*bpf_map_delete_elem_t)(struct bpf_map *map, const void *key);
static bpf_map_delete_elem_t bpf_map_delete_elem = (bpf_map_delete_elem_t) 3;

typedef long (*bpf_probe_read_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_t bpf_probe_read = (bpf_probe_read_t) 4;

typedef u64 (*bpf_ktime_get_ns_t)();
static bpf_ktime_get_ns_t bpf_ktime_get_ns = (bpf_ktime_get_ns_t) 5;

typedef long (*bpf_trace_printk_t)(const char *, u64, ...);
static bpf_trace_printk_t bpf_trace_printk = (bpf_trace_printk_t) 6;

typedef u32 (*bpf_get_prandom_u32_t)();
static bpf_get_prandom_u32_t bpf_get_prandom_u32 = (bpf_get_prandom_u32_t) 7;

typedef u32 (*bpf_get_smp_processor_id_t)();
static bpf_get_smp_processor_id_t bpf_get_smp_processor_id = (bpf_get_smp_processor_id_t) 8;

typedef long (*bpf_skb_store_bytes_t)(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags);
static bpf_skb_store_bytes_t bpf_skb_store_bytes = (bpf_skb_store_bytes_t) 9;

typedef long (*bpf_l3_csum_replace_t)(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 size);
static bpf_l3_csum_replace_t bpf_l3_csum_replace = (bpf_l3_csum_replace_t) 10;

typedef long (*bpf_l4_csum_replace_t)(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags);
static bpf_l4_csum_replace_t bpf_l4_csum_replace = (bpf_l4_csum_replace_t) 11;

typedef long (*bpf_tail_call_t)(void *ctx, struct bpf_map *prog_array_map, u32 index);
static bpf_tail_call_t bpf_tail_call = (bpf_tail_call_t) 12;

typedef long (*bpf_clone_redirect_t)(struct sk_buff *skb, u32 ifindex, u64 flags);
static bpf_clone_redirect_t bpf_clone_redirect = (bpf_clone_redirect_t) 13;

typedef u64 (*bpf_get_current_pid_tgid_t)();
static bpf_get_current_pid_tgid_t bpf_get_current_pid_tgid = (bpf_get_current_pid_tgid_t) 14;

typedef u64 (*bpf_get_current_uid_gid_t)();
static bpf_get_current_uid_gid_t bpf_get_current_uid_gid = (bpf_get_current_uid_gid_t) 15;

typedef long (*bpf_get_current_comm_t)(void *buf, u32 size_of_buf);
static bpf_get_current_comm_t bpf_get_current_comm = (bpf_get_current_comm_t) 16;

typedef u32 (*bpf_get_cgroup_classid_t)(struct sk_buff *skb);
static bpf_get_cgroup_classid_t bpf_get_cgroup_classid = (bpf_get_cgroup_classid_t) 17;

typedef long (*bpf_skb_vlan_push_t)(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci);
static bpf_skb_vlan_push_t bpf_skb_vlan_push = (bpf_skb_vlan_push_t) 18;

typedef long (*bpf_skb_vlan_pop_t)(struct sk_buff *skb);
static bpf_skb_vlan_pop_t bpf_skb_vlan_pop = (bpf_skb_vlan_pop_t) 19;

typedef long (*bpf_skb_get_tunnel_key_t)(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags);
static bpf_skb_get_tunnel_key_t bpf_skb_get_tunnel_key = (bpf_skb_get_tunnel_key_t) 20;

typedef long (*bpf_skb_set_tunnel_key_t)(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags);
static bpf_skb_set_tunnel_key_t bpf_skb_set_tunnel_key = (bpf_skb_set_tunnel_key_t) 21;

typedef u64 (*bpf_perf_event_read_t)(struct bpf_map *map, u64 flags);
static bpf_perf_event_read_t bpf_perf_event_read = (bpf_perf_event_read_t) 22;

typedef long (*bpf_redirect_t)(u32 ifindex, u64 flags);
static bpf_redirect_t bpf_redirect = (bpf_redirect_t) 23;

typedef u32 (*bpf_get_route_realm_t)(struct sk_buff *skb);
static bpf_get_route_realm_t bpf_get_route_realm = (bpf_get_route_realm_t) 24;

typedef long (*bpf_perf_event_output_t)(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size);
static bpf_perf_event_output_t bpf_perf_event_output = (bpf_perf_event_output_t) 25;

typedef long (*bpf_skb_load_bytes_t)(const void *skb, u32 offset, void *to, u32 len);
static bpf_skb_load_bytes_t bpf_skb_load_bytes = (bpf_skb_load_bytes_t) 26;

typedef long (*bpf_get_stackid_t)(void *ctx, struct bpf_map *map, u64 flags);
static bpf_get_stackid_t bpf_get_stackid = (bpf_get_stackid_t) 27;

typedef s64 (*bpf_csum_diff_t)(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed);
static bpf_csum_diff_t bpf_csum_diff = (bpf_csum_diff_t) 28;

typedef long (*bpf_skb_get_tunnel_opt_t)(struct sk_buff *skb, void *opt, u32 size);
static bpf_skb_get_tunnel_opt_t bpf_skb_get_tunnel_opt = (bpf_skb_get_tunnel_opt_t) 29;

typedef long (*bpf_skb_set_tunnel_opt_t)(struct sk_buff *skb, void *opt, u32 size);
static bpf_skb_set_tunnel_opt_t bpf_skb_set_tunnel_opt = (bpf_skb_set_tunnel_opt_t) 30;

typedef long (*bpf_skb_change_proto_t)(struct sk_buff *skb, __be16 proto, u64 flags);
static bpf_skb_change_proto_t bpf_skb_change_proto = (bpf_skb_change_proto_t) 31;

typedef long (*bpf_skb_change_type_t)(struct sk_buff *skb, u32 type);
static bpf_skb_change_type_t bpf_skb_change_type = (bpf_skb_change_type_t) 32;

typedef long (*bpf_skb_under_cgroup_t)(struct sk_buff *skb, struct bpf_map *map, u32 index);
static bpf_skb_under_cgroup_t bpf_skb_under_cgroup = (bpf_skb_under_cgroup_t) 33;

typedef u32 (*bpf_get_hash_recalc_t)(struct sk_buff *skb);
static bpf_get_hash_recalc_t bpf_get_hash_recalc = (bpf_get_hash_recalc_t) 34;

typedef u64 (*bpf_get_current_task_t)();
static bpf_get_current_task_t bpf_get_current_task = (bpf_get_current_task_t) 35;

typedef long (*bpf_probe_write_user_t)(void *dst, const void *src, u32 len);
static bpf_probe_write_user_t bpf_probe_write_user = (bpf_probe_write_user_t) 36;

typedef long (*bpf_current_task_under_cgroup_t)(struct bpf_map *map, u32 index);
static bpf_current_task_under_cgroup_t bpf_current_task_under_cgroup = (bpf_current_task_under_cgroup_t) 37;

typedef long (*bpf_skb_change_tail_t)(struct sk_buff *skb, u32 len, u64 flags);
static bpf_skb_change_tail_t bpf_skb_change_tail = (bpf_skb_change_tail_t) 38;

typedef long (*bpf_skb_pull_data_t)(struct sk_buff *skb, u32 len);
static bpf_skb_pull_data_t bpf_skb_pull_data = (bpf_skb_pull_data_t) 39;

typedef s64 (*bpf_csum_update_t)(struct sk_buff *skb, __wsum csum);
static bpf_csum_update_t bpf_csum_update = (bpf_csum_update_t) 40;

typedef void (*bpf_set_hash_invalid_t)(struct sk_buff *skb);
static bpf_set_hash_invalid_t bpf_set_hash_invalid = (bpf_set_hash_invalid_t) 41;

typedef long (*bpf_get_numa_node_id_t)();
static bpf_get_numa_node_id_t bpf_get_numa_node_id = (bpf_get_numa_node_id_t) 42;

typedef long (*bpf_skb_change_head_t)(struct sk_buff *skb, u32 len, u64 flags);
static bpf_skb_change_head_t bpf_skb_change_head = (bpf_skb_change_head_t) 43;

typedef long (*bpf_xdp_adjust_head_t)(struct xdp_buff *xdp_md, int delta);
static bpf_xdp_adjust_head_t bpf_xdp_adjust_head = (bpf_xdp_adjust_head_t) 44;

typedef long (*bpf_probe_read_str_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_str_t bpf_probe_read_str = (bpf_probe_read_str_t) 45;

// There are 4 possible overloads for this in the bpf.h header; since
// we can't do function overloading in C, just use a `void *` parameter
typedef u64 (*bpf_get_socket_cookie_t)(void *ctx);
static bpf_get_socket_cookie_t bpf_get_socket_cookie = (bpf_get_socket_cookie_t) 46;

typedef u64 (*bpf_get_socket_uid_t)(struct sk_buff *skb);
static bpf_get_socket_uid_t bpf_get_socket_uid = (bpf_get_socket_uid_t) 47;

typedef long (*bpf_set_hash_t)(struct sk_buff *skb, u32 hash);
static bpf_set_hash_t bpf_set_hash = (bpf_set_hash_t) 48;

typedef long (*bpf_setsockopt_t)(void *bpf_socket, int level, int optname, void *optval, int optlen);
static bpf_setsockopt_t bpf_setsockopt = (bpf_setsockopt_t) 49;

typedef long (*bpf_skb_adjust_room_t)(struct sk_buff *skb, s32 len_diff, u32 mode, u64 flags);
static bpf_skb_adjust_room_t bpf_skb_adjust_room = (bpf_skb_adjust_room_t) 50;

typedef long (*bpf_redirect_map_t)(struct bpf_map *map, u32 key, u64 flags);
static bpf_redirect_map_t bpf_redirect_map = (bpf_redirect_map_t) 51;

typedef long (*bpf_sk_redirect_map_t)(struct sk_buff *skb, struct bpf_map *map, u32 key, u64 flags);
static bpf_sk_redirect_map_t bpf_sk_redirect_map = (bpf_sk_redirect_map_t) 52;

typedef long (*bpf_sock_map_update_t)(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags);
static bpf_sock_map_update_t bpf_sock_map_update = (bpf_sock_map_update_t) 53;

typedef long (*bpf_xdp_adjust_meta_t)(struct xdp_buff *xdp_md, int delta);
static bpf_xdp_adjust_meta_t bpf_xdp_adjust_meta = (bpf_xdp_adjust_meta_t) 54;

typedef long (*bpf_perf_event_read_value_t)(struct bpf_map *map, u64 flags, struct bpf_perf_event_value *buf, u32 buf_size);
static bpf_perf_event_read_value_t bpf_perf_event_read_value = (bpf_perf_event_read_value_t) 55;

typedef long (*bpf_perf_prog_read_value_t)(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, u32 buf_size);
static bpf_perf_prog_read_value_t bpf_perf_prog_read_value = (bpf_perf_prog_read_value_t) 56;

typedef long (*bpf_getsockopt_t)(void *bpf_socket, int level, int optname, void *optval, int optlen);
static bpf_getsockopt_t bpf_getsockopt = (bpf_getsockopt_t) 57;

typedef long (*bpf_override_return_t)(struct pt_regs *regs, u64 rc);
static bpf_override_return_t bpf_override_return = (bpf_override_return_t) 58;

typedef long (*bpf_sock_ops_cb_flags_set_t)(struct bpf_sock_ops *bpf_sock, int argval);
static bpf_sock_ops_cb_flags_set_t bpf_sock_ops_cb_flags_set = (bpf_sock_ops_cb_flags_set_t) 59;

typedef long (*bpf_msg_redirect_map_t)(struct sk_msg_buff *msg, struct bpf_map *map, u32 key, u64 flags);
static bpf_msg_redirect_map_t bpf_msg_redirect_map = (bpf_msg_redirect_map_t) 60;

typedef long (*bpf_msg_apply_bytes_t)(struct sk_msg_buff *msg, u32 bytes);
static bpf_msg_apply_bytes_t bpf_msg_apply_bytes = (bpf_msg_apply_bytes_t) 61;

typedef long (*bpf_msg_cork_bytes_t)(struct sk_msg_buff *msg, u32 bytes);
static bpf_msg_cork_bytes_t bpf_msg_cork_bytes = (bpf_msg_cork_bytes_t) 62;

typedef long (*bpf_msg_pull_data_t)(struct sk_msg_buff *msg, u32 start, u32 end, u64 flags);
static bpf_msg_pull_data_t bpf_msg_pull_data = (bpf_msg_pull_data_t) 63;

typedef long (*bpf_bind_t)(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len);
static bpf_bind_t bpf_bind = (bpf_bind_t) 64;

typedef long (*bpf_xdp_adjust_tail_t)(struct xdp_buff *xdp_md, int delta);
static bpf_xdp_adjust_tail_t bpf_xdp_adjust_tail = (bpf_xdp_adjust_tail_t) 65;

typedef long (*bpf_skb_get_xfrm_state_t)(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags);
static bpf_skb_get_xfrm_state_t bpf_skb_get_xfrm_state = (bpf_skb_get_xfrm_state_t) 66;

typedef long (*bpf_get_stack_t)(void *ctx, void *buf, u32 size, u64 flags);
static bpf_get_stack_t bpf_get_stack = (bpf_get_stack_t) 67;

typedef long (*bpf_skb_load_bytes_relative_t)(const void *skb, u32 offset, void *to, u32 len, u32 start_header);
static bpf_skb_load_bytes_relative_t bpf_skb_load_bytes_relative = (bpf_skb_load_bytes_relative_t) 68;

typedef long (*bpf_fib_lookup_t)(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags);
static bpf_fib_lookup_t bpf_fib_lookup = (bpf_fib_lookup_t) 69;

typedef long (*bpf_sock_hash_update_t)(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags);
static bpf_sock_hash_update_t bpf_sock_hash_update = (bpf_sock_hash_update_t) 70;

typedef long (*bpf_msg_redirect_hash_t)(struct sk_msg_buff *msg, struct bpf_map *map, void *key, u64 flags);
static bpf_msg_redirect_hash_t bpf_msg_redirect_hash = (bpf_msg_redirect_hash_t) 71;

typedef long (*bpf_sk_redirect_hash_t)(struct sk_buff *skb, struct bpf_map *map, void *key, u64 flags);
static bpf_sk_redirect_hash_t bpf_sk_redirect_hash = (bpf_sk_redirect_hash_t) 72;

typedef long (*bpf_lwt_push_encap_t)(struct sk_buff *skb, u32 type, void *hdr, u32 len);
static bpf_lwt_push_encap_t bpf_lwt_push_encap = (bpf_lwt_push_encap_t) 73;

typedef long (*bpf_lwt_seg6_store_bytes_t)(struct sk_buff *skb, u32 offset, const void *from, u32 len);
static bpf_lwt_seg6_store_bytes_t bpf_lwt_seg6_store_bytes = (bpf_lwt_seg6_store_bytes_t) 74;

typedef long (*bpf_lwt_seg6_adjust_srh_t)(struct sk_buff *skb, u32 offset, s32 delta);
static bpf_lwt_seg6_adjust_srh_t bpf_lwt_seg6_adjust_srh = (bpf_lwt_seg6_adjust_srh_t) 75;

typedef long (*bpf_lwt_seg6_action_t)(struct sk_buff *skb, u32 action, void *param, u32 param_len);
static bpf_lwt_seg6_action_t bpf_lwt_seg6_action = (bpf_lwt_seg6_action_t) 76;

typedef long (*bpf_rc_repeat_t)(void *ctx);
static bpf_rc_repeat_t bpf_rc_repeat = (bpf_rc_repeat_t) 77;

typedef long (*bpf_rc_keydown_t)(void *ctx, u32 protocol, u64 scancode, u32 toggle);
static bpf_rc_keydown_t bpf_rc_keydown = (bpf_rc_keydown_t) 78;

typedef u64 (*bpf_skb_cgroup_id_t)(struct sk_buff *skb);
static bpf_skb_cgroup_id_t bpf_skb_cgroup_id = (bpf_skb_cgroup_id_t) 79;

typedef u64 (*bpf_get_current_cgroup_id_t)();
static bpf_get_current_cgroup_id_t bpf_get_current_cgroup_id = (bpf_get_current_cgroup_id_t) 80;

typedef void *(*bpf_get_local_storage_t)(void *map, u64 flags);
static bpf_get_local_storage_t bpf_get_local_storage = (bpf_get_local_storage_t) 81;

typedef long (*bpf_sk_select_reuseport_t)(struct sk_reuseport_md *reuse, struct bpf_map *map, void *key, u64 flags);
static bpf_sk_select_reuseport_t bpf_sk_select_reuseport = (bpf_sk_select_reuseport_t) 82;

typedef u64 (*bpf_skb_ancestor_cgroup_id_t)(struct sk_buff *skb, int ancestor_level);
static bpf_skb_ancestor_cgroup_id_t bpf_skb_ancestor_cgroup_id = (bpf_skb_ancestor_cgroup_id_t) 83;

typedef struct bpf_sock * (*bpf_sk_lookup_tcp_t)(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static bpf_sk_lookup_tcp_t bpf_sk_lookup_tcp = (bpf_sk_lookup_tcp_t) 84;

typedef struct bpf_sock * (*bpf_sk_lookup_udp_t)(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static bpf_sk_lookup_udp_t bpf_sk_lookup_udp = (bpf_sk_lookup_udp_t) 85;

typedef long (*bpf_sk_release_t)(void *sock);
static bpf_sk_release_t bpf_sk_release = (bpf_sk_release_t) 86;

typedef long (*bpf_map_push_elem_t)(struct bpf_map *map, const void *value, u64 flags);
static bpf_map_push_elem_t bpf_map_push_elem = (bpf_map_push_elem_t) 87;

typedef long (*bpf_map_pop_elem_t)(struct bpf_map *map, void *value);
static bpf_map_pop_elem_t bpf_map_pop_elem = (bpf_map_pop_elem_t) 88;

typedef long (*bpf_map_peek_elem_t)(struct bpf_map *map, void *value);
static bpf_map_peek_elem_t bpf_map_peek_elem = (bpf_map_peek_elem_t) 89;

typedef long (*bpf_msg_push_data_t)(struct sk_msg_buff *msg, u32 start, u32 len, u64 flags);
static bpf_msg_push_data_t bpf_msg_push_data = (bpf_msg_push_data_t) 90;

typedef long (*bpf_msg_pop_data_t)(struct sk_msg_buff *msg, u32 start, u32 len, u64 flags);
static bpf_msg_pop_data_t bpf_msg_pop_data = (bpf_msg_pop_data_t) 91;

typedef long (*bpf_rc_pointer_rel_t)(void *ctx, s32 rel_x, s32 rel_y);
static bpf_rc_pointer_rel_t bpf_rc_pointer_rel = (bpf_rc_pointer_rel_t) 92;

typedef long (*bpf_spin_lock_t)(struct bpf_spin_lock *lock);
static bpf_spin_lock_t bpf_spin_lock = (bpf_spin_lock_t) 93;

typedef long (*bpf_spin_unlock_t)(struct bpf_spin_lock *lock);
static bpf_spin_unlock_t bpf_spin_unlock = (bpf_spin_unlock_t) 94;

typedef struct bpf_sock * (*bpf_sk_fullsock_t)(struct bpf_sock *sk);
static bpf_sk_fullsock_t bpf_sk_fullsock = (bpf_sk_fullsock_t) 95;

typedef struct bpf_tcp_sock * (*bpf_tcp_sock_t)(struct bpf_sock *sk);
static bpf_tcp_sock_t bpf_tcp_sock = (bpf_tcp_sock_t) 96;

typedef long (*bpf_skb_ecn_set_ce_t)(struct sk_buff *skb);
static bpf_skb_ecn_set_ce_t bpf_skb_ecn_set_ce = (bpf_skb_ecn_set_ce_t) 97;

typedef struct bpf_sock * (*bpf_get_listener_sock_t)(struct bpf_sock *sk);
static bpf_get_listener_sock_t bpf_get_listener_sock = (bpf_get_listener_sock_t) 98;

typedef struct bpf_sock * (*bpf_skc_lookup_tcp_t)(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static bpf_skc_lookup_tcp_t bpf_skc_lookup_tcp = (bpf_skc_lookup_tcp_t) 99;

typedef long (*bpf_tcp_check_syncookie_t)(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len);
static bpf_tcp_check_syncookie_t bpf_tcp_check_syncookie = (bpf_tcp_check_syncookie_t) 100;

typedef long (*bpf_sysctl_get_name_t)(struct bpf_sysctl *ctx, char *buf, size_t buf_len, u64 flags);
static bpf_sysctl_get_name_t bpf_sysctl_get_name = (bpf_sysctl_get_name_t) 101;

typedef long (*bpf_sysctl_get_current_value_t)(struct bpf_sysctl *ctx, char *buf, size_t buf_len);
static bpf_sysctl_get_current_value_t bpf_sysctl_get_current_value = (bpf_sysctl_get_current_value_t) 102;

typedef long (*bpf_sysctl_get_new_value_t)(struct bpf_sysctl *ctx, char *buf, size_t buf_len);
static bpf_sysctl_get_new_value_t bpf_sysctl_get_new_value = (bpf_sysctl_get_new_value_t) 103;

typedef long (*bpf_sysctl_set_new_value_t)(struct bpf_sysctl *ctx, const char *buf, size_t buf_len);
static bpf_sysctl_set_new_value_t bpf_sysctl_set_new_value = (bpf_sysctl_set_new_value_t) 104;

typedef long (*bpf_strtol_t)(const char *buf, size_t buf_len, u64 flags, long *res);
static bpf_strtol_t bpf_strtol = (bpf_strtol_t) 105;

typedef long (*bpf_strtoul_t)(const char *buf, size_t buf_len, u64 flags, unsigned long *res);
static bpf_strtoul_t bpf_strtoul = (bpf_strtoul_t) 106;

typedef void *(*bpf_sk_storage_get_t)(struct bpf_map *map, void *sk, void *value, u64 flags);
static bpf_sk_storage_get_t bpf_sk_storage_get = (bpf_sk_storage_get_t) 107;

typedef long (*bpf_sk_storage_delete_t)(struct bpf_map *map, void *sk);
static bpf_sk_storage_delete_t bpf_sk_storage_delete = (bpf_sk_storage_delete_t) 108;

typedef long (*bpf_send_signal_t)(u32 sig);
static bpf_send_signal_t bpf_send_signal = (bpf_send_signal_t) 109;

typedef s64 (*bpf_tcp_gen_syncookie_t)(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len);
static bpf_tcp_gen_syncookie_t bpf_tcp_gen_syncookie = (bpf_tcp_gen_syncookie_t) 110;

typedef long (*bpf_skb_output_t)(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size);
static bpf_skb_output_t bpf_skb_output = (bpf_skb_output_t) 111;

typedef long (*bpf_probe_read_user_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_user_t bpf_probe_read_user = (bpf_probe_read_user_t) 112;

typedef long (*bpf_probe_read_kernel_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_kernel_t bpf_probe_read_kernel = (bpf_probe_read_kernel_t) 113;

typedef long (*bpf_probe_read_user_str_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_user_str_t bpf_probe_read_user_str = (bpf_probe_read_user_str_t) 114;

typedef long (*bpf_probe_read_kernel_str_t)(void *dst, u32 size, const void *unsafe_ptr);
static bpf_probe_read_kernel_str_t bpf_probe_read_kernel_str = (bpf_probe_read_kernel_str_t) 115;

typedef long (*bpf_tcp_send_ack_t)(void *tp, u32 rcv_nxt);
static bpf_tcp_send_ack_t bpf_tcp_send_ack = (bpf_tcp_send_ack_t) 116;

typedef long (*bpf_send_signal_thread_t)(u32 sig);
static bpf_send_signal_thread_t bpf_send_signal_thread = (bpf_send_signal_thread_t) 117;

typedef u64 (*bpf_jiffies64_t)();
static bpf_jiffies64_t bpf_jiffies64 = (bpf_jiffies64_t) 118;

typedef long (*bpf_read_branch_records_t)(struct bpf_perf_event_data *ctx, void *buf, u32 size, u64 flags);
static bpf_read_branch_records_t bpf_read_branch_records = (bpf_read_branch_records_t) 119;

typedef long (*bpf_get_ns_current_pid_tgid_t)(u64 dev, u64 ino, struct bpf_pidns_info *nsdata, u32 size);
static bpf_get_ns_current_pid_tgid_t bpf_get_ns_current_pid_tgid = (bpf_get_ns_current_pid_tgid_t) 120;

typedef long (*bpf_xdp_output_t)(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size);
static bpf_xdp_output_t bpf_xdp_output = (bpf_xdp_output_t) 121;

typedef u64 (*bpf_get_netns_cookie_t)(void *ctx);
static bpf_get_netns_cookie_t bpf_get_netns_cookie = (bpf_get_netns_cookie_t) 122;

typedef u64 (*bpf_get_current_ancestor_cgroup_id_t)(int ancestor_level);
static bpf_get_current_ancestor_cgroup_id_t bpf_get_current_ancestor_cgroup_id = (bpf_get_current_ancestor_cgroup_id_t) 123;

// There are two overloads for this function, and which one is used depends
// on the program type. Use `void *` as a parameter
typedef long (*bpf_sk_assign_t)(void *ctx, void *sk, u64 flags);
static bpf_sk_assign_t bpf_sk_assign = (bpf_sk_assign_t) 124;

typedef u64 (*bpf_ktime_get_boot_ns_t)();
static bpf_ktime_get_boot_ns_t bpf_ktime_get_boot_ns = (bpf_ktime_get_boot_ns_t) 125;

typedef long (*bpf_seq_printf_t)(struct seq_file *m, const char *fmt, u32 fmt_size, const void *data, u32 data_len);
static bpf_seq_printf_t bpf_seq_printf = (bpf_seq_printf_t) 126;

typedef long (*bpf_seq_write_t)(struct seq_file *m, const void *data, u32 len);
static bpf_seq_write_t bpf_seq_write = (bpf_seq_write_t) 127;

typedef u64 (*bpf_sk_cgroup_id_t)(void *sk);
static bpf_sk_cgroup_id_t bpf_sk_cgroup_id = (bpf_sk_cgroup_id_t) 128;

typedef u64 (*bpf_sk_ancestor_cgroup_id_t)(void *sk, int ancestor_level);
static bpf_sk_ancestor_cgroup_id_t bpf_sk_ancestor_cgroup_id = (bpf_sk_ancestor_cgroup_id_t) 129;

typedef long (*bpf_ringbuf_output_t)(void *ringbuf, void *data, u64 size, u64 flags);
static bpf_ringbuf_output_t bpf_ringbuf_output = (bpf_ringbuf_output_t) 130;

typedef void *(*bpf_ringbuf_reserve_t)(void *ringbuf, u64 size, u64 flags);
static bpf_ringbuf_reserve_t bpf_ringbuf_reserve = (bpf_ringbuf_reserve_t) 131;

typedef void (*bpf_ringbuf_submit_t)(void *data, u64 flags);
static bpf_ringbuf_submit_t bpf_ringbuf_submit = (bpf_ringbuf_submit_t) 132;

typedef void (*bpf_ringbuf_discard_t)(void *data, u64 flags);
static bpf_ringbuf_discard_t bpf_ringbuf_discard = (bpf_ringbuf_discard_t) 133;

typedef u64 (*bpf_ringbuf_query_t)(void *ringbuf, u64 flags);
static bpf_ringbuf_query_t bpf_ringbuf_query = (bpf_ringbuf_query_t) 134;

typedef long (*bpf_csum_level_t)(struct sk_buff *skb, u64 level);
static bpf_csum_level_t bpf_csum_level = (bpf_csum_level_t) 135;

typedef struct tcp6_sock *(*bpf_skc_to_tcp6_sock_t)(void *sk);
static bpf_skc_to_tcp6_sock_t bpf_skc_to_tcp6_sock = (bpf_skc_to_tcp6_sock_t) 136;

typedef struct tcp_sock * (*bpf_skc_to_tcp_sock_t)(void *sk);
static bpf_skc_to_tcp_sock_t bpf_skc_to_tcp_sock = (bpf_skc_to_tcp_sock_t) 137;

typedef struct tcp_timewait_sock * (*bpf_skc_to_tcp_timewait_sock_t)(void *sk);
static bpf_skc_to_tcp_timewait_sock_t bpf_skc_to_tcp_timewait_sock = (bpf_skc_to_tcp_timewait_sock_t) 138;

typedef struct tcp_request_sock * (*bpf_skc_to_tcp_request_sock_t)(void *sk);
static bpf_skc_to_tcp_request_sock_t bpf_skc_to_tcp_request_sock = (bpf_skc_to_tcp_request_sock_t) 139;

typedef struct udp6_sock * (*bpf_skc_to_udp6_sock_t)(void *sk);
static bpf_skc_to_udp6_sock_t bpf_skc_to_udp6_sock = (bpf_skc_to_udp6_sock_t) 140;

typedef long (*bpf_get_task_stack_t)(struct task_struct *task, void *buf, u32 size, u64 flags);
static bpf_get_task_stack_t bpf_get_task_stack = (bpf_get_task_stack_t) 141;

typedef long (*bpf_load_hdr_opt_t)(struct bpf_sock_ops *skops, void *searchby_res, u32 len, u64 flags);
static bpf_load_hdr_opt_t bpf_load_hdr_opt = (bpf_load_hdr_opt_t) 142;

typedef long (*bpf_store_hdr_opt_t)(struct bpf_sock_ops *skops, const void *from, u32 len, u64 flags);
static bpf_store_hdr_opt_t bpf_store_hdr_opt = (bpf_store_hdr_opt_t) 143;

typedef long (*bpf_reserve_hdr_opt_t)(struct bpf_sock_ops *skops, u32 len, u64 flags);
static bpf_reserve_hdr_opt_t bpf_reserve_hdr_opt = (bpf_reserve_hdr_opt_t) 144;

typedef void *(*bpf_inode_storage_get_t)(struct bpf_map *map, void *inode, void *value, u64 flags);
static bpf_inode_storage_get_t bpf_inode_storage_get = (bpf_inode_storage_get_t) 145;

typedef int (*bpf_inode_storage_delete_t)(struct bpf_map *map, void *inode);
static bpf_inode_storage_delete_t bpf_inode_storage_delete = (bpf_inode_storage_delete_t) 146;

typedef long (*bpf_d_path_t)(struct path *path, char *buf, u32 sz);
static bpf_d_path_t bpf_d_path = (bpf_d_path_t) 147;

typedef long (*bpf_copy_from_user_t)(void *dst, u32 size, const void *user_ptr);
static bpf_copy_from_user_t bpf_copy_from_user = (bpf_copy_from_user_t) 148;

typedef long (*bpf_snprintf_btf_t)(char *str, u32 str_size, struct btf_ptr *ptr, u32 btf_ptr_size, u64 flags);
static bpf_snprintf_btf_t bpf_snprintf_btf = (bpf_snprintf_btf_t) 149;

typedef long (*bpf_seq_printf_btf_t)(struct seq_file *m, struct btf_ptr *ptr, u32 ptr_size, u64 flags);
static bpf_seq_printf_btf_t bpf_seq_printf_btf = (bpf_seq_printf_btf_t) 150;

typedef u64 (*bpf_skb_cgroup_classid_t)(struct sk_buff *skb);
static bpf_skb_cgroup_classid_t bpf_skb_cgroup_classid = (bpf_skb_cgroup_classid_t) 151;

typedef long (*bpf_redirect_neigh_t)(u32 ifindex, struct bpf_redir_neigh *params, int plen, u64 flags);
static bpf_redirect_neigh_t bpf_redirect_neigh = (bpf_redirect_neigh_t) 152;

typedef void *(*bpf_per_cpu_ptr_t)(const void *percpu_ptr, u32 cpu);
static bpf_per_cpu_ptr_t bpf_per_cpu_ptr = (bpf_per_cpu_ptr_t) 153;

typedef void *(*bpf_this_cpu_ptr_t)(const void *percpu_ptr);
static bpf_this_cpu_ptr_t bpf_this_cpu_ptr = (bpf_this_cpu_ptr_t) 154;

typedef long (*bpf_redirect_peer_t)(u32 ifindex, u64 flags);
static bpf_redirect_peer_t bpf_redirect_peer = (bpf_redirect_peer_t) 155;

typedef void *(*bpf_task_storage_get_t)(struct bpf_map *map, struct task_struct *task, void *value, u64 flags);
static bpf_task_storage_get_t bpf_task_storage_get = (bpf_task_storage_get_t) 156;

typedef long (*bpf_task_storage_delete_t)(struct bpf_map *map, struct task_struct *task);
static bpf_task_storage_delete_t bpf_task_storage_delete = (bpf_task_storage_delete_t) 157;

typedef struct task_struct * (*bpf_get_current_task_btf_t)();
static bpf_get_current_task_btf_t bpf_get_current_task_btf = (bpf_get_current_task_btf_t) 158;

typedef long (*bpf_bprm_opts_set_t)(struct linux_binprm *bprm, u64 flags);
static bpf_bprm_opts_set_t bpf_bprm_opts_set = (bpf_bprm_opts_set_t) 159;

typedef u64 (*bpf_ktime_get_coarse_ns_t)();
static bpf_ktime_get_coarse_ns_t bpf_ktime_get_coarse_ns = (bpf_ktime_get_coarse_ns_t) 160;

typedef long (*bpf_ima_inode_hash_t)(struct inode *inode, void *dst, u32 size);
static bpf_ima_inode_hash_t bpf_ima_inode_hash = (bpf_ima_inode_hash_t) 161;

typedef struct socket *(*bpf_sock_from_file_t)(struct file *file);
static bpf_sock_from_file_t bpf_sock_from_file = (bpf_sock_from_file_t) 162;

typedef long (*bpf_check_mtu_t)(void *ctx, u32 ifindex, u32 *mtu_len, s32 len_diff, u64 flags);
static bpf_check_mtu_t bpf_check_mtu = (bpf_check_mtu_t) 163;

typedef long (*bpf_for_each_map_elem_t)(struct bpf_map *map, void *callback_fn, void *callback_ctx, u64 flags);
static bpf_for_each_map_elem_t bpf_for_each_map_elem = (bpf_for_each_map_elem_t) 164;

typedef long (*bpf_snprintf_t)(char *str, u32 str_size, const char *fmt, u64 *data, u32 data_len);
static bpf_snprintf_t bpf_snprintf = (bpf_snprintf_t) 165;

typedef long (*bpf_sys_bpf_t)(u32 cmd, void *attr, u32 attr_size);
static bpf_sys_bpf_t bpf_sys_bpf = (bpf_sys_bpf_t) 166;

typedef long (*bpf_btf_find_by_name_kind_t)(char *name, int name_sz, u32 kind, int flags);
static bpf_btf_find_by_name_kind_t bpf_btf_find_by_name_kind = (bpf_btf_find_by_name_kind_t) 167;

typedef long (*bpf_sys_close_t)(u32 fd);
static bpf_sys_close_t bpf_sys_close = (bpf_sys_close_t) 168;

typedef long (*bpf_timer_init_t)(struct bpf_timer *timer, struct bpf_map *map, u64 flags);
static bpf_timer_init_t bpf_timer_init = (bpf_timer_init_t) 169;

typedef long (*bpf_timer_set_callback_t)(struct bpf_timer *timer, void *callback_fn);
static bpf_timer_set_callback_t bpf_timer_set_callback = (bpf_timer_set_callback_t) 170;

typedef long (*bpf_timer_start_t)(struct bpf_timer *timer, u64 nsecs, u64 flags);
static bpf_timer_start_t bpf_timer_start = (bpf_timer_start_t) 171;

typedef long (*bpf_timer_cancel_t)(struct bpf_timer *timer);
static bpf_timer_cancel_t bpf_timer_cancel = (bpf_timer_cancel_t) 172;

typedef u64 (*bpf_get_func_ip_t)();
static bpf_get_func_ip_t bpf_get_func_ip = (bpf_get_func_ip_t) 173;

typedef u64 (*bpf_get_attach_cookie_t)(void *ctx);
static bpf_get_attach_cookie_t bpf_get_attach_cookie = (bpf_get_attach_cookie_t) 174;

typedef long (*bpf_task_pt_regs_t)(struct task_struct *task);
static bpf_task_pt_regs_t bpf_task_pt_regs = (bpf_task_pt_regs_t) 175;

typedef long (*bpf_get_branch_snapshot_t)(void *entries, u32 size, u64 flags);
static bpf_get_branch_snapshot_t bpf_get_branch_snapshot = (bpf_get_branch_snapshot_t) 176;

typedef long (*bpf_trace_vprintk_t)(const char *fmt, u32 fmt_size, const void *data, u32 data_len);
static bpf_trace_vprintk_t bpf_trace_vprintk = (bpf_trace_vprintk_t) 177;

typedef struct unix_sock * (*bpf_skc_to_unix_sock_t)(void *sk);
static bpf_skc_to_unix_sock_t bpf_skc_to_unix_sock = (bpf_skc_to_unix_sock_t) 178;

typedef long (*bpf_kallsyms_lookup_name_t)(const char *name, int name_sz, int flags, u64 *res);
static bpf_kallsyms_lookup_name_t bpf_kallsyms_lookup_name = (bpf_kallsyms_lookup_name_t) 179;

typedef long (*bpf_find_vma_t)(struct task_struct *task, u64 addr, void *callback_fn, void *callback_ctx, u64 flags);
static bpf_find_vma_t bpf_find_vma = (bpf_find_vma_t) 180;

typedef long (*bpf_loop_t)(u32 nr_loops, void *callback_fn, void *callback_ctx, u64 flags);
static bpf_loop_t bpf_loop = (bpf_loop_t) 181;

typedef long (*bpf_strncmp_t)(const char *s1, u32 s1_sz, const char *s2);
static bpf_strncmp_t bpf_strncmp = (bpf_strncmp_t) 182;

typedef long (*bpf_get_func_arg_t)(void *ctx, u32 n, u64 *value);
static bpf_get_func_arg_t bpf_get_func_arg = (bpf_get_func_arg_t) 183;

typedef long (*bpf_get_func_ret_t)(void *ctx, u64 *value);
static bpf_get_func_ret_t bpf_get_func_ret = (bpf_get_func_ret_t) 184;

typedef long (*bpf_get_func_arg_cnt_t)(void *ctx);
static bpf_get_func_arg_cnt_t bpf_get_func_arg_cnt = (bpf_get_func_arg_cnt_t) 185;

typedef int (*bpf_get_retval_t)();
static bpf_get_retval_t bpf_get_retval = (bpf_get_retval_t) 186;

typedef int (*bpf_set_retval_t)(int retval);
static bpf_set_retval_t bpf_set_retval = (bpf_set_retval_t) 187;

typedef u64 (*bpf_xdp_get_buff_len_t)(struct xdp_buff *xdp_md);
static bpf_xdp_get_buff_len_t bpf_xdp_get_buff_len = (bpf_xdp_get_buff_len_t) 188;

typedef long (*bpf_xdp_load_bytes_t)(struct xdp_buff *xdp_md, u32 offset, void *buf, u32 len);
static bpf_xdp_load_bytes_t bpf_xdp_load_bytes = (bpf_xdp_load_bytes_t) 189;

typedef long (*bpf_xdp_store_bytes_t)(struct xdp_buff *xdp_md, u32 offset, void *buf, u32 len);
static bpf_xdp_store_bytes_t bpf_xdp_store_bytes = (bpf_xdp_store_bytes_t) 190;

typedef long (*bpf_copy_from_user_task_t)(void *dst, u32 size, const void *user_ptr, struct task_struct *tsk, u64 flags);
static bpf_copy_from_user_task_t bpf_copy_from_user_task = (bpf_copy_from_user_task_t) 191;

typedef long (*bpf_skb_set_tstamp_t)(struct sk_buff *skb, u64 tstamp, u32 tstamp_type);
static bpf_skb_set_tstamp_t bpf_skb_set_tstamp = (bpf_skb_set_tstamp_t) 192;

typedef long (*bpf_ima_file_hash_t)(struct file *file, void *dst, u32 size);
static bpf_ima_file_hash_t bpf_ima_file_hash = (bpf_ima_file_hash_t) 193;

typedef void *(*bpf_kptr_xchg_t)(void *map_value, void *ptr);
static bpf_kptr_xchg_t bpf_kptr_xchg = (bpf_kptr_xchg_t) 194;

typedef void *(*bpf_map_lookup_percpu_elem_t)(struct bpf_map *map, const void *key, u32 cpu);
static bpf_map_lookup_percpu_elem_t bpf_map_lookup_percpu_elem = (bpf_map_lookup_percpu_elem_t) 195;

typedef struct mptcp_sock * (*bpf_skc_to_mptcp_sock_t)(void *sk);
static bpf_skc_to_mptcp_sock_t bpf_skc_to_mptcp_sock = (bpf_skc_to_mptcp_sock_t) 196;

typedef long (*bpf_dynptr_from_mem_t)(void *data, u32 size, u64 flags, struct bpf_dynptr *ptr);
static bpf_dynptr_from_mem_t bpf_dynptr_from_mem = (bpf_dynptr_from_mem_t) 197;

typedef long (*bpf_ringbuf_reserve_dynptr_t)(void *ringbuf, u32 size, u64 flags, struct bpf_dynptr *ptr);
static bpf_ringbuf_reserve_dynptr_t bpf_ringbuf_reserve_dynptr = (bpf_ringbuf_reserve_dynptr_t) 198;

typedef void (*bpf_ringbuf_submit_dynptr_t)(struct bpf_dynptr *ptr, u64 flags);
static bpf_ringbuf_submit_dynptr_t bpf_ringbuf_submit_dynptr = (bpf_ringbuf_submit_dynptr_t) 199;

typedef void (*bpf_ringbuf_discard_dynptr_t)(struct bpf_dynptr *ptr, u64 flags);
static bpf_ringbuf_discard_dynptr_t bpf_ringbuf_discard_dynptr = (bpf_ringbuf_discard_dynptr_t) 200;

typedef long (*bpf_dynptr_read_t)(void *dst, u32 len, struct bpf_dynptr *src, u32 offset, u64 flags);
static bpf_dynptr_read_t bpf_dynptr_read = (bpf_dynptr_read_t) 201;

typedef long (*bpf_dynptr_write_t)(struct bpf_dynptr *dst, u32 offset, void *src, u32 len, u64 flags);
static bpf_dynptr_write_t bpf_dynptr_write = (bpf_dynptr_write_t) 202;

typedef void *(*bpf_dynptr_data_t)(struct bpf_dynptr *ptr, u32 offset, u32 len);
static bpf_dynptr_data_t bpf_dynptr_data = (bpf_dynptr_data_t) 203;
)src"};
// clang-format on

} // namespace tob::ebpf
