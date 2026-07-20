#pragma once

#include <stddef.h>

namespace mesh {

template <typename T, size_t Capacity>
class BoundedQueue {
  static_assert(Capacity > 0, "BoundedQueue capacity must be greater than zero");

  T _items[Capacity];
  size_t _head = 0;
  size_t _size = 0;

public:
  bool push(const T& item) {
    if (_size == Capacity) return false;
    _items[(_head + _size) % Capacity] = item;
    _size++;
    return true;
  }

  bool pop(T& item) {
    if (_size == 0) return false;
    item = _items[_head];
    _head = (_head + 1) % Capacity;
    _size--;
    return true;
  }

  void clear() {
    _head = 0;
    _size = 0;
  }

  size_t size() const { return _size; }
};

}  // namespace mesh
