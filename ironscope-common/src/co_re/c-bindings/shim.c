#include "c-types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ------------------------------------------------------------------ */
/* Macros                                                              */
/* ------------------------------------------------------------------ */

#define _SHIM_GETTER(ret, proto, accessed_member)                \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return __builtin_preserve_access_index(accessed_member); \
	}

#define _SHIM_GETTER_BPF_CORE_READ(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                 \
	{                                                        \
		return BPF_CORE_READ(struc, memb);                   \
	}

#define _SHIM_GETTER_BPF_CORE_READ_USER(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                      \
	{                                                             \
		return BPF_CORE_READ_USER(struc, memb);                   \
	}

#define _FIELD_EXISTS_DEF(_struct, memb, memb_name)                                                        \
	__attribute__((always_inline)) _Bool shim_##_struct##_##memb_name##_##exists(struct _struct *_struct)  \
	{                                                                                                      \
		return bpf_core_field_exists(_struct->memb);                                                       \
	}

#define SHIM(struc, memb)                                                                                                      \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb)    \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM_REF(struc, memb)                                                                                            \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb(struct struc *struc), &(struc->memb))       \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb)) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM(struc, memb)                                                                                                \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb(struct struc *struc), &(struc->memb[0]))      \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

/* ------------------------------------------------------------------ */
/* task_struct                                                         */
/* ------------------------------------------------------------------ */

struct mm_struct;

struct task_struct {
	unsigned int flags;
	pid_t pid;
	pid_t tgid;
	unsigned char comm[COMM_LEN];
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct mm_struct *mm;
} __attribute__((preserve_access_index));

SHIM(task_struct, flags);
SHIM(task_struct, pid);
SHIM(task_struct, tgid);
ARRAY_SHIM(task_struct, comm);
SHIM(task_struct, real_parent);
SHIM(task_struct, group_leader);
SHIM(task_struct, mm);

/* ------------------------------------------------------------------ */
/* mm_struct                                                           */
/* ------------------------------------------------------------------ */

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
	struct file *exe_file;
} __attribute__((preserve_access_index));

SHIM(mm_struct, arg_start);
SHIM(mm_struct, arg_end);
SHIM(mm_struct, exe_file);

/* ------------------------------------------------------------------ */
/* super_block                                                         */
/* ------------------------------------------------------------------ */

struct super_block {
	unsigned long s_dev;
	struct dentry *s_root;
} __attribute__((preserve_access_index));

SHIM(super_block, s_dev);
SHIM(super_block, s_root);

/* ------------------------------------------------------------------ */
/* inode                                                                */
/* ------------------------------------------------------------------ */

struct inode {
	unsigned long i_ino;
	u16 i_mode;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

SHIM(inode, i_ino);
SHIM(inode, i_mode);
SHIM(inode, i_sb);

/* ------------------------------------------------------------------ */
/* qstr                                                                */
/* ------------------------------------------------------------------ */

struct qstr {
	__u64 hash_len;
	const unsigned char *name;
} __attribute__((preserve_access_index));

SHIM(qstr, name);
SHIM(qstr, hash_len);

/* ------------------------------------------------------------------ */
/* dentry                                                              */
/* ------------------------------------------------------------------ */

struct dentry {
	unsigned int d_flags;
	struct dentry *d_parent;
	struct qstr d_name;
	struct super_block *d_sb;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

SHIM(dentry, d_flags);
SHIM(dentry, d_parent);
SHIM_REF(dentry, d_name);
SHIM(dentry, d_sb);
SHIM(dentry, d_inode);

/* ------------------------------------------------------------------ */
/* path / vfsmount / mount                                             */
/* ------------------------------------------------------------------ */

struct vfsmount {
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

SHIM(vfsmount, mnt_root);

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
} __attribute__((preserve_access_index));

SHIM(mount, mnt_parent);
SHIM(mount, mnt_mountpoint);
SHIM_REF(mount, mnt);

/* container_of: get mount from embedded vfsmount */
__attribute__((always_inline)) struct mount *shim_mount_from_vfsmount(struct vfsmount *vfs) {
	struct mount *m = 0;
	struct vfsmount *v = __builtin_preserve_access_index(&(m->mnt));
	__u64 offset = (void *)v - (void *)m;
	return ((void *)vfs - offset);
}

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

SHIM(path, mnt);
SHIM(path, dentry);

/* ------------------------------------------------------------------ */
/* file                                                                */
/* ------------------------------------------------------------------ */

struct file {
	struct path f_path;
	struct inode *f_inode;
	unsigned int f_flags;
} __attribute__((preserve_access_index));

SHIM_REF(file, f_path);
SHIM(file, f_inode);
SHIM(file, f_flags);

/* ------------------------------------------------------------------ */
/* linux_binprm                                                        */
/* ------------------------------------------------------------------ */

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

SHIM(linux_binprm, file);

/* ------------------------------------------------------------------ */
/* sockaddr_in                                                         */
/* ------------------------------------------------------------------ */

struct sockaddr {
	unsigned short sa_family;
} __attribute__((preserve_access_index));

SHIM(sockaddr, sa_family);

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct {
		__be32 s_addr;
	} sin_addr;
} __attribute__((preserve_access_index));

SHIM(sockaddr_in, sin_family);
SHIM(sockaddr_in, sin_port);

__attribute__((always_inline)) __be32 shim_sockaddr_in_s_addr(struct sockaddr_in *sa) {
	return BPF_CORE_READ(sa, sin_addr.s_addr);
}

__attribute__((always_inline)) _Bool shim_sockaddr_in_s_addr_exists(struct sockaddr_in *sa) {
	return bpf_core_field_exists(sa->sin_addr);
}
