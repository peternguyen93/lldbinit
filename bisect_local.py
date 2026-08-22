#
# bisec.py
# LLDB python used python 3.9 which doesn't support
# key argument for bisect_* api, this is copy code from newest bisec
#
from typing import List, Optional, Callable, Any, TypeVar

T = TypeVar('T')
def bisect_left(a: List[T],
				x: T,
				lo: int=0,
				hi: Optional[int]=None,
				*,
				key: Optional[Callable[[Any], Any]]=None) -> int:
	"""Return the index where to insert item x in list a, assuming a is sorted.

	The return value i is such that all e in a[:i] have e < x, and all e in
	a[i:] have e >= x.  So if x already appears in the list, a.insert(i, x) will
	insert just before the leftmost x already there.

	Optional args lo (default 0) and hi (default len(a)) bound the
	slice of a to be searched.

	A custom key function can be supplied to customize the sort order.
	"""

	if lo < 0:
		raise ValueError('lo must be non-negative')
	if hi is None:
		hi = len(a)
	# Note, the comparison uses "<" to match the
	# __lt__() logic in list.sort() and in heapq.
	if key is None:
		while lo < hi:
			mid = (lo + hi) // 2
			if a[mid] < x:
				lo = mid + 1
			else:
				hi = mid
	else:
		while lo < hi:
			mid = (lo + hi) // 2
			if key(a[mid]) < key(x):
				lo = mid + 1
			else:
				hi = mid
	return lo