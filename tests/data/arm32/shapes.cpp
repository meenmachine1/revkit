// The fixture's C++ (shapes.h), built with -fno-rtti -fno-exceptions.
#include "shapes.h"

#include "kit.h"

void *operator new(unsigned int n);
static unsigned char g_heap[1024];
static unsigned int g_heap_used;

void *operator new(unsigned int n) {
  n = (n + 7) & ~7u;
  if (g_heap_used + n > sizeof g_heap) return nullptr;
  void *p = g_heap + g_heap_used;
  g_heap_used += n;
  return p;
}
void operator delete(void *) noexcept {}
void operator delete(void *, unsigned int) noexcept {}
extern "C" void __cxa_pure_virtual() {
  for (;;) {
  }
}

Shape::Shape(int id_) : id(id_), x(0), y(0), flags(1) {}
Shape::~Shape() { flags = 0; }
void Shape::scale(int k) { flags |= k << 8; }
void Shape::move(int dx, int dy) {
  x += dx;
  y += dy;
  flags |= 2;
}

Rect::Rect(int id_, int w_, int h_) : Shape(id_), w(w_), h(h_) {}
int Rect::area() const { return w * h; }
void Rect::scale(int k) {
  w *= k;
  h *= k;
  Shape::scale(k);
}

Circle::Circle(int id_, int r_) : Shape(id_), r(r_) {}
int Circle::area() const { return 3 * r * r + (r >> 2); }
void Circle::scale(int k) {
  r *= k;
  flags |= 4;
}

