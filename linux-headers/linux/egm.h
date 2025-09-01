#ifndef EGM_H
#define EGM_H

#define EGM_TYPE       ('E')

struct egm_retired_pages_info {
	__aligned_u64 offset;
	__aligned_u64 size;
};

struct egm_retired_pages_list {
	__u32 argsz;
	/* out */
	__u32 count;
	/* out */
	struct egm_retired_pages_info retired_pages[];
};
#define EGM_RETIRED_PAGES_LIST     _IO(EGM_TYPE, 100)

#endif /* EGM_H */
