/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef GU_INTERVAL_ARRAY_HELPER_H
#define GU_INTERVAL_ARRAY_HELPER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * struct interval_array_item_u32 - Compact 32-bit interval entry.
 * @start: Inclusive interval start.
 * @end: Exclusive interval end.
 * @private: Caller-owned payload pointer.
 */
struct interval_array_item_u32 {
	uint32_t start;
	uint32_t end;
	void *private;
};

/**
 * struct interval_array_item - 64-bit interval entry.
 * @start: Inclusive interval start.
 * @end: Exclusive interval end.
 * @private: Caller-owned payload pointer.
 */
struct interval_array_item {
	uint64_t start;
	uint64_t end;
	void *private;
};

#define interval_array_item_u64 interval_array_item

/**
 * enum interval_array_type - Backing storage width.
 * @INTERVAL_ARRAY_TYPE_U32: Store intervals in 32-bit compact entries.
 * @INTERVAL_ARRAY_TYPE_U64: Store intervals in 64-bit entries.
 */
enum interval_array_type {
	INTERVAL_ARRAY_TYPE_U32,
	INTERVAL_ARRAY_TYPE_U64,
};

/**
 * struct interval_array - Sorted searchable interval array.
 * @items_u32: Compact 32-bit backing entries.
 * @items_u64: 64-bit backing entries.
 * @count: Number of intervals.
 * @type: Active backing storage type.
 * @min: Lowest interval start.
 * @max: Highest interval end.
 */
struct interval_array {
	struct interval_array_item_u32 *items_u32;
	struct interval_array_item_u64 *items_u64;

	int count;

	enum interval_array_type type;

	uint64_t min;
	uint64_t max;
};

/**
 * gu_interval_array_init() - Build a sorted interval array.
 * @items: Input intervals. The array is sorted in place.
 * @count: Number of input intervals.
 *
 * Return: New interval array, or NULL on failure.
 */
struct interval_array *gu_interval_array_init(struct interval_array_item *items, int count);

/**
 * gu_interval_array_destroy() - Free an interval array and owned payloads.
 * @array: Interval array to free.
 */
void gu_interval_array_destroy(struct interval_array *array);

/**
 * gu_interval_array_search() - Find the interval containing an address.
 * @array: Interval array to search.
 * @addr: Address to locate.
 * @item: Output interval entry.
 *
 * Return: Matching index on success, or a negative value on failure.
 */
int gu_interval_array_search(struct interval_array *array, uint64_t addr, struct interval_array_item *item);

/**
 * gu_interval_array_search_set_no_free() - Find an interval and preserve payload ownership.
 * @array: Interval array to search.
 * @addr: Address to locate.
 * @item: Output interval entry.
 *
 * Return: Matching index on success, or a negative value on failure.
 */
int gu_interval_array_search_set_no_free(struct interval_array *array, uint64_t addr, struct interval_array_item *item);

/**
 * mark_interval_array_pointer_no_free() - Mark a payload pointer as externally owned.
 * @ptr_value: Pointer value to mark.
 *
 * The high bit is used as an ownership tag because interval payloads are aligned
 * pointers in this codebase.
 *
 * Return: Tagged pointer value.
 */
static inline uint64_t mark_interval_array_pointer_no_free(uint64_t ptr_value)
{
	ptr_value |= (1ULL << 63);
	return ptr_value;
}

/**
 * get_interval_array_pointer() - Untag an interval payload pointer.
 * @ptr_value: Tagged pointer value.
 * @no_free: Optional output ownership tag.
 *
 * Return: Original payload pointer.
 */
static inline void *get_interval_array_pointer(uint64_t ptr_value, bool *no_free)
{
	bool is_marked = (ptr_value & (1ULL << 63)) != 0;

	if (no_free)
		*no_free = is_marked;

	ptr_value &= ~(1ULL << 63);
	return (void *)ptr_value;
}

/**
 * typedef private_process_p - Interval payload visitor.
 * @pointer: Untagged payload pointer.
 * @ctx: Caller-provided visitor context.
 */
typedef void (*private_process_p)(void *pointer, void *ctx);

/**
 * gu_interval_array_for_each_private() - Visit all non-NULL payload pointers.
 * @array: Interval array to walk.
 * @func: Visitor callback.
 * @ctx: Caller-provided visitor context.
 */
void gu_interval_array_for_each_private(struct interval_array *array, private_process_p func, void *ctx);

#endif /* GU_INTERVAL_ARRAY_HELPER_H */
